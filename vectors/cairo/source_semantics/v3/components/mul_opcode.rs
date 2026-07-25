// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::mul_opcode::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    memory_address_to_id, memory_id_to_big, range_check_20, verify_instruction,
};
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
        range_check_20_state: &range_check_20::ClaimGenerator,
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
            range_check_20_state,
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
        for inputs in sub_component_inputs.range_check_20 {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_20_b {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_20_c {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 2);
        }
        for inputs in sub_component_inputs.range_check_20_d {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 3);
        }
        for inputs in sub_component_inputs.range_check_20_e {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 4);
        }
        for inputs in sub_component_inputs.range_check_20_f {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 5);
        }
        for inputs in sub_component_inputs.range_check_20_g {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 6);
        }
        for inputs in sub_component_inputs.range_check_20_h {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 7);
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 3],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 3],
    range_check_20: [Vec<range_check_20::PackedInputType>; 4],
    range_check_20_b: [Vec<range_check_20::PackedInputType>; 4],
    range_check_20_c: [Vec<range_check_20::PackedInputType>; 4],
    range_check_20_d: [Vec<range_check_20::PackedInputType>; 4],
    range_check_20_e: [Vec<range_check_20::PackedInputType>; 3],
    range_check_20_f: [Vec<range_check_20::PackedInputType>; 3],
    range_check_20_g: [Vec<range_check_20::PackedInputType>; 3],
    range_check_20_h: [Vec<range_check_20::PackedInputType>; 3],
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
    range_check_20_state: &range_check_20::ClaimGenerator,
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
    let M31_128 = PackedM31::broadcast(M31::from(128));
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1410849886 = PackedM31::broadcast(M31::from(1410849886));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_4194304 = PackedM31::broadcast(M31::from(4194304));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_447122465 = PackedM31::broadcast(M31::from(447122465));
    let M31_463900084 = PackedM31::broadcast(M31::from(463900084));
    let M31_480677703 = PackedM31::broadcast(M31::from(480677703));
    let M31_497455322 = PackedM31::broadcast(M31::from(497455322));
    let M31_514232941 = PackedM31::broadcast(M31::from(514232941));
    let M31_524288 = PackedM31::broadcast(M31::from(524288));
    let M31_531010560 = PackedM31::broadcast(M31::from(531010560));
    let M31_64 = PackedM31::broadcast(M31::from(64));
    let M31_65536 = PackedM31::broadcast(M31::from(65536));
    let M31_682009131 = PackedM31::broadcast(M31::from(682009131));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let UInt16_0 = PackedUInt16::broadcast(UInt16::from(0));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_127 = PackedUInt16::broadcast(UInt16::from(127));
    let UInt16_13 = PackedUInt16::broadcast(UInt16::from(13));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
    let UInt16_31 = PackedUInt16::broadcast(UInt16::from(31));
    let UInt16_4 = PackedUInt16::broadcast(UInt16::from(4));
    let UInt16_5 = PackedUInt16::broadcast(UInt16::from(5));
    let UInt16_6 = PackedUInt16::broadcast(UInt16::from(6));
    let UInt16_7 = PackedUInt16::broadcast(UInt16::from(7));
    let UInt16_9 = PackedUInt16::broadcast(UInt16::from(9));
    let UInt32_131072 = PackedUInt32::broadcast(UInt32::from(131072));
    let UInt32_262143 = PackedUInt32::broadcast(UInt32::from(262143));
    let UInt32_511 = PackedUInt32::broadcast(UInt32::from(511));
    let UInt32_9 = PackedUInt32::broadcast(UInt32::from(9));
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
            |(row_index, (row, lookup_data, sub_component_inputs, mul_opcode_input))| {
                let input_pc_col0 = mul_opcode_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = mul_opcode_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = mul_opcode_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_93be2_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_93be2_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_93be2_0);
                let offset0_tmp_93be2_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_93be2_2.as_m31();
                *row[3] = offset0_col3;
                let offset1_tmp_93be2_3 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(1)))
                        >> (UInt16_7))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(2),
                        )) << (UInt16_2)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(3),
                        )) & (UInt16_31))
                            << (UInt16_11)));
                let offset1_col4 = offset1_tmp_93be2_3.as_m31();
                *row[4] = offset1_col4;
                let offset2_tmp_93be2_4 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(3)))
                        >> (UInt16_5))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(4),
                        )) << (UInt16_4)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(5),
                        )) & (UInt16_7))
                            << (UInt16_13)));
                let offset2_col5 = offset2_tmp_93be2_4.as_m31();
                *row[5] = offset2_col5;
                let dst_base_fp_tmp_93be2_5 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col6 = dst_base_fp_tmp_93be2_5.as_m31();
                *row[6] = dst_base_fp_col6;
                let op0_base_fp_tmp_93be2_6 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_1))
                        & (UInt16_1));
                let op0_base_fp_col7 = op0_base_fp_tmp_93be2_6.as_m31();
                *row[7] = op0_base_fp_col7;
                let op1_imm_tmp_93be2_7 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_2))
                        & (UInt16_1));
                let op1_imm_col8 = op1_imm_tmp_93be2_7.as_m31();
                *row[8] = op1_imm_col8;
                let op1_base_fp_tmp_93be2_8 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_3))
                        & (UInt16_1));
                let op1_base_fp_col9 = op1_base_fp_tmp_93be2_8.as_m31();
                *row[9] = op1_base_fp_col9;
                let op1_base_ap_tmp_93be2_9 = (((M31_1) - (op1_imm_col8)) - (op1_base_fp_col9));
                let ap_update_add_1_tmp_93be2_10 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_93be2_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_93be2_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col10 = ap_update_add_1_tmp_93be2_10.as_m31();
                *row[10] = ap_update_add_1_col10;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, offset1_col4, offset2_col5],
                    [
                        ((((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                            + ((op1_imm_col8) * (M31_32)))
                            + ((op1_base_fp_col9) * (M31_64)))
                            + ((op1_base_ap_tmp_93be2_9) * (M31_128))),
                        (((M31_1) + ((ap_update_add_1_col10) * (M31_32))) + (M31_256)),
                    ],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    offset0_col3,
                    offset1_col4,
                    offset2_col5,
                    ((((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                        + ((op1_imm_col8) * (M31_32)))
                        + ((op1_base_fp_col9) * (M31_64)))
                        + ((op1_base_ap_tmp_93be2_9) * (M31_128))),
                    (((M31_1) + ((ap_update_add_1_col10) * (M31_32))) + (M31_256)),
                    M31_0,
                ];
                let decode_instruction_c630b_output_tmp_93be2_11 = (
                    [
                        ((offset0_col3) - (M31_32768)),
                        ((offset1_col4) - (M31_32768)),
                        ((offset2_col5) - (M31_32768)),
                    ],
                    [
                        dst_base_fp_col6,
                        op0_base_fp_col7,
                        op1_imm_col8,
                        op1_base_fp_col9,
                        op1_base_ap_tmp_93be2_9,
                        M31_0,
                        M31_1,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        ap_update_add_1_col10,
                        M31_0,
                        M31_0,
                        M31_1,
                    ],
                    M31_0,
                );

                let mem_dst_base_col11 = (((dst_base_fp_col6) * (input_fp_col2))
                    + (((M31_1) - (dst_base_fp_col6)) * (input_ap_col1)));
                *row[11] = mem_dst_base_col11;
                let mem0_base_col12 = (((op0_base_fp_col7) * (input_fp_col2))
                    + (((M31_1) - (op0_base_fp_col7)) * (input_ap_col1)));
                *row[12] = mem0_base_col12;
                let mem1_base_col13 = ((((op1_imm_col8) * (input_pc_col0))
                    + ((op1_base_fp_col9) * (input_fp_col2)))
                    + ((decode_instruction_c630b_output_tmp_93be2_11.1[4]) * (input_ap_col1)));
                *row[13] = mem1_base_col13;

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_93be2_12 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col11)
                            + (decode_instruction_c630b_output_tmp_93be2_11.0[0])),
                    );
                let dst_id_col14 = memory_address_to_id_value_tmp_93be2_12;
                *row[14] = dst_id_col14;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem_dst_base_col11) + (decode_instruction_c630b_output_tmp_93be2_11.0[0]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem_dst_base_col11) + (decode_instruction_c630b_output_tmp_93be2_11.0[0])),
                    dst_id_col14,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_93be2_14 =
                    memory_id_to_big_state.deduce_output(dst_id_col14);
                let dst_limb_0_col15 = memory_id_to_big_value_tmp_93be2_14.get_m31(0);
                *row[15] = dst_limb_0_col15;
                let dst_limb_1_col16 = memory_id_to_big_value_tmp_93be2_14.get_m31(1);
                *row[16] = dst_limb_1_col16;
                let dst_limb_2_col17 = memory_id_to_big_value_tmp_93be2_14.get_m31(2);
                *row[17] = dst_limb_2_col17;
                let dst_limb_3_col18 = memory_id_to_big_value_tmp_93be2_14.get_m31(3);
                *row[18] = dst_limb_3_col18;
                let dst_limb_4_col19 = memory_id_to_big_value_tmp_93be2_14.get_m31(4);
                *row[19] = dst_limb_4_col19;
                let dst_limb_5_col20 = memory_id_to_big_value_tmp_93be2_14.get_m31(5);
                *row[20] = dst_limb_5_col20;
                let dst_limb_6_col21 = memory_id_to_big_value_tmp_93be2_14.get_m31(6);
                *row[21] = dst_limb_6_col21;
                let dst_limb_7_col22 = memory_id_to_big_value_tmp_93be2_14.get_m31(7);
                *row[22] = dst_limb_7_col22;
                let dst_limb_8_col23 = memory_id_to_big_value_tmp_93be2_14.get_m31(8);
                *row[23] = dst_limb_8_col23;
                let dst_limb_9_col24 = memory_id_to_big_value_tmp_93be2_14.get_m31(9);
                *row[24] = dst_limb_9_col24;
                let dst_limb_10_col25 = memory_id_to_big_value_tmp_93be2_14.get_m31(10);
                *row[25] = dst_limb_10_col25;
                let dst_limb_11_col26 = memory_id_to_big_value_tmp_93be2_14.get_m31(11);
                *row[26] = dst_limb_11_col26;
                let dst_limb_12_col27 = memory_id_to_big_value_tmp_93be2_14.get_m31(12);
                *row[27] = dst_limb_12_col27;
                let dst_limb_13_col28 = memory_id_to_big_value_tmp_93be2_14.get_m31(13);
                *row[28] = dst_limb_13_col28;
                let dst_limb_14_col29 = memory_id_to_big_value_tmp_93be2_14.get_m31(14);
                *row[29] = dst_limb_14_col29;
                let dst_limb_15_col30 = memory_id_to_big_value_tmp_93be2_14.get_m31(15);
                *row[30] = dst_limb_15_col30;
                let dst_limb_16_col31 = memory_id_to_big_value_tmp_93be2_14.get_m31(16);
                *row[31] = dst_limb_16_col31;
                let dst_limb_17_col32 = memory_id_to_big_value_tmp_93be2_14.get_m31(17);
                *row[32] = dst_limb_17_col32;
                let dst_limb_18_col33 = memory_id_to_big_value_tmp_93be2_14.get_m31(18);
                *row[33] = dst_limb_18_col33;
                let dst_limb_19_col34 = memory_id_to_big_value_tmp_93be2_14.get_m31(19);
                *row[34] = dst_limb_19_col34;
                let dst_limb_20_col35 = memory_id_to_big_value_tmp_93be2_14.get_m31(20);
                *row[35] = dst_limb_20_col35;
                let dst_limb_21_col36 = memory_id_to_big_value_tmp_93be2_14.get_m31(21);
                *row[36] = dst_limb_21_col36;
                let dst_limb_22_col37 = memory_id_to_big_value_tmp_93be2_14.get_m31(22);
                *row[37] = dst_limb_22_col37;
                let dst_limb_23_col38 = memory_id_to_big_value_tmp_93be2_14.get_m31(23);
                *row[38] = dst_limb_23_col38;
                let dst_limb_24_col39 = memory_id_to_big_value_tmp_93be2_14.get_m31(24);
                *row[39] = dst_limb_24_col39;
                let dst_limb_25_col40 = memory_id_to_big_value_tmp_93be2_14.get_m31(25);
                *row[40] = dst_limb_25_col40;
                let dst_limb_26_col41 = memory_id_to_big_value_tmp_93be2_14.get_m31(26);
                *row[41] = dst_limb_26_col41;
                let dst_limb_27_col42 = memory_id_to_big_value_tmp_93be2_14.get_m31(27);
                *row[42] = dst_limb_27_col42;
                *sub_component_inputs.memory_id_to_big[0] = dst_id_col14;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    dst_id_col14,
                    dst_limb_0_col15,
                    dst_limb_1_col16,
                    dst_limb_2_col17,
                    dst_limb_3_col18,
                    dst_limb_4_col19,
                    dst_limb_5_col20,
                    dst_limb_6_col21,
                    dst_limb_7_col22,
                    dst_limb_8_col23,
                    dst_limb_9_col24,
                    dst_limb_10_col25,
                    dst_limb_11_col26,
                    dst_limb_12_col27,
                    dst_limb_13_col28,
                    dst_limb_14_col29,
                    dst_limb_15_col30,
                    dst_limb_16_col31,
                    dst_limb_17_col32,
                    dst_limb_18_col33,
                    dst_limb_19_col34,
                    dst_limb_20_col35,
                    dst_limb_21_col36,
                    dst_limb_22_col37,
                    dst_limb_23_col38,
                    dst_limb_24_col39,
                    dst_limb_25_col40,
                    dst_limb_26_col41,
                    dst_limb_27_col42,
                ];
                let read_positive_known_id_num_bits_252_output_tmp_93be2_15 =
                    PackedFelt252::from_limbs([
                        dst_limb_0_col15,
                        dst_limb_1_col16,
                        dst_limb_2_col17,
                        dst_limb_3_col18,
                        dst_limb_4_col19,
                        dst_limb_5_col20,
                        dst_limb_6_col21,
                        dst_limb_7_col22,
                        dst_limb_8_col23,
                        dst_limb_9_col24,
                        dst_limb_10_col25,
                        dst_limb_11_col26,
                        dst_limb_12_col27,
                        dst_limb_13_col28,
                        dst_limb_14_col29,
                        dst_limb_15_col30,
                        dst_limb_16_col31,
                        dst_limb_17_col32,
                        dst_limb_18_col33,
                        dst_limb_19_col34,
                        dst_limb_20_col35,
                        dst_limb_21_col36,
                        dst_limb_22_col37,
                        dst_limb_23_col38,
                        dst_limb_24_col39,
                        dst_limb_25_col40,
                        dst_limb_26_col41,
                        dst_limb_27_col42,
                    ]);

                let read_positive_num_bits_252_output_tmp_93be2_16 = (
                    read_positive_known_id_num_bits_252_output_tmp_93be2_15,
                    dst_id_col14,
                );

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_93be2_17 = memory_address_to_id_state
                    .deduce_output(
                        ((mem0_base_col12) + (decode_instruction_c630b_output_tmp_93be2_11.0[1])),
                    );
                let op0_id_col43 = memory_address_to_id_value_tmp_93be2_17;
                *row[43] = op0_id_col43;
                *sub_component_inputs.memory_address_to_id[1] =
                    ((mem0_base_col12) + (decode_instruction_c630b_output_tmp_93be2_11.0[1]));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((mem0_base_col12) + (decode_instruction_c630b_output_tmp_93be2_11.0[1])),
                    op0_id_col43,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_93be2_19 =
                    memory_id_to_big_state.deduce_output(op0_id_col43);
                let op0_limb_0_col44 = memory_id_to_big_value_tmp_93be2_19.get_m31(0);
                *row[44] = op0_limb_0_col44;
                let op0_limb_1_col45 = memory_id_to_big_value_tmp_93be2_19.get_m31(1);
                *row[45] = op0_limb_1_col45;
                let op0_limb_2_col46 = memory_id_to_big_value_tmp_93be2_19.get_m31(2);
                *row[46] = op0_limb_2_col46;
                let op0_limb_3_col47 = memory_id_to_big_value_tmp_93be2_19.get_m31(3);
                *row[47] = op0_limb_3_col47;
                let op0_limb_4_col48 = memory_id_to_big_value_tmp_93be2_19.get_m31(4);
                *row[48] = op0_limb_4_col48;
                let op0_limb_5_col49 = memory_id_to_big_value_tmp_93be2_19.get_m31(5);
                *row[49] = op0_limb_5_col49;
                let op0_limb_6_col50 = memory_id_to_big_value_tmp_93be2_19.get_m31(6);
                *row[50] = op0_limb_6_col50;
                let op0_limb_7_col51 = memory_id_to_big_value_tmp_93be2_19.get_m31(7);
                *row[51] = op0_limb_7_col51;
                let op0_limb_8_col52 = memory_id_to_big_value_tmp_93be2_19.get_m31(8);
                *row[52] = op0_limb_8_col52;
                let op0_limb_9_col53 = memory_id_to_big_value_tmp_93be2_19.get_m31(9);
                *row[53] = op0_limb_9_col53;
                let op0_limb_10_col54 = memory_id_to_big_value_tmp_93be2_19.get_m31(10);
                *row[54] = op0_limb_10_col54;
                let op0_limb_11_col55 = memory_id_to_big_value_tmp_93be2_19.get_m31(11);
                *row[55] = op0_limb_11_col55;
                let op0_limb_12_col56 = memory_id_to_big_value_tmp_93be2_19.get_m31(12);
                *row[56] = op0_limb_12_col56;
                let op0_limb_13_col57 = memory_id_to_big_value_tmp_93be2_19.get_m31(13);
                *row[57] = op0_limb_13_col57;
                let op0_limb_14_col58 = memory_id_to_big_value_tmp_93be2_19.get_m31(14);
                *row[58] = op0_limb_14_col58;
                let op0_limb_15_col59 = memory_id_to_big_value_tmp_93be2_19.get_m31(15);
                *row[59] = op0_limb_15_col59;
                let op0_limb_16_col60 = memory_id_to_big_value_tmp_93be2_19.get_m31(16);
                *row[60] = op0_limb_16_col60;
                let op0_limb_17_col61 = memory_id_to_big_value_tmp_93be2_19.get_m31(17);
                *row[61] = op0_limb_17_col61;
                let op0_limb_18_col62 = memory_id_to_big_value_tmp_93be2_19.get_m31(18);
                *row[62] = op0_limb_18_col62;
                let op0_limb_19_col63 = memory_id_to_big_value_tmp_93be2_19.get_m31(19);
                *row[63] = op0_limb_19_col63;
                let op0_limb_20_col64 = memory_id_to_big_value_tmp_93be2_19.get_m31(20);
                *row[64] = op0_limb_20_col64;
                let op0_limb_21_col65 = memory_id_to_big_value_tmp_93be2_19.get_m31(21);
                *row[65] = op0_limb_21_col65;
                let op0_limb_22_col66 = memory_id_to_big_value_tmp_93be2_19.get_m31(22);
                *row[66] = op0_limb_22_col66;
                let op0_limb_23_col67 = memory_id_to_big_value_tmp_93be2_19.get_m31(23);
                *row[67] = op0_limb_23_col67;
                let op0_limb_24_col68 = memory_id_to_big_value_tmp_93be2_19.get_m31(24);
                *row[68] = op0_limb_24_col68;
                let op0_limb_25_col69 = memory_id_to_big_value_tmp_93be2_19.get_m31(25);
                *row[69] = op0_limb_25_col69;
                let op0_limb_26_col70 = memory_id_to_big_value_tmp_93be2_19.get_m31(26);
                *row[70] = op0_limb_26_col70;
                let op0_limb_27_col71 = memory_id_to_big_value_tmp_93be2_19.get_m31(27);
                *row[71] = op0_limb_27_col71;
                *sub_component_inputs.memory_id_to_big[1] = op0_id_col43;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    op0_id_col43,
                    op0_limb_0_col44,
                    op0_limb_1_col45,
                    op0_limb_2_col46,
                    op0_limb_3_col47,
                    op0_limb_4_col48,
                    op0_limb_5_col49,
                    op0_limb_6_col50,
                    op0_limb_7_col51,
                    op0_limb_8_col52,
                    op0_limb_9_col53,
                    op0_limb_10_col54,
                    op0_limb_11_col55,
                    op0_limb_12_col56,
                    op0_limb_13_col57,
                    op0_limb_14_col58,
                    op0_limb_15_col59,
                    op0_limb_16_col60,
                    op0_limb_17_col61,
                    op0_limb_18_col62,
                    op0_limb_19_col63,
                    op0_limb_20_col64,
                    op0_limb_21_col65,
                    op0_limb_22_col66,
                    op0_limb_23_col67,
                    op0_limb_24_col68,
                    op0_limb_25_col69,
                    op0_limb_26_col70,
                    op0_limb_27_col71,
                ];
                let read_positive_known_id_num_bits_252_output_tmp_93be2_20 =
                    PackedFelt252::from_limbs([
                        op0_limb_0_col44,
                        op0_limb_1_col45,
                        op0_limb_2_col46,
                        op0_limb_3_col47,
                        op0_limb_4_col48,
                        op0_limb_5_col49,
                        op0_limb_6_col50,
                        op0_limb_7_col51,
                        op0_limb_8_col52,
                        op0_limb_9_col53,
                        op0_limb_10_col54,
                        op0_limb_11_col55,
                        op0_limb_12_col56,
                        op0_limb_13_col57,
                        op0_limb_14_col58,
                        op0_limb_15_col59,
                        op0_limb_16_col60,
                        op0_limb_17_col61,
                        op0_limb_18_col62,
                        op0_limb_19_col63,
                        op0_limb_20_col64,
                        op0_limb_21_col65,
                        op0_limb_22_col66,
                        op0_limb_23_col67,
                        op0_limb_24_col68,
                        op0_limb_25_col69,
                        op0_limb_26_col70,
                        op0_limb_27_col71,
                    ]);

                let read_positive_num_bits_252_output_tmp_93be2_21 = (
                    read_positive_known_id_num_bits_252_output_tmp_93be2_20,
                    op0_id_col43,
                );

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_93be2_22 = memory_address_to_id_state
                    .deduce_output(
                        ((mem1_base_col13) + (decode_instruction_c630b_output_tmp_93be2_11.0[2])),
                    );
                let op1_id_col72 = memory_address_to_id_value_tmp_93be2_22;
                *row[72] = op1_id_col72;
                *sub_component_inputs.memory_address_to_id[2] =
                    ((mem1_base_col13) + (decode_instruction_c630b_output_tmp_93be2_11.0[2]));
                *lookup_data.memory_address_to_id_5 = [
                    M31_1444891767,
                    ((mem1_base_col13) + (decode_instruction_c630b_output_tmp_93be2_11.0[2])),
                    op1_id_col72,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_93be2_24 =
                    memory_id_to_big_state.deduce_output(op1_id_col72);
                let op1_limb_0_col73 = memory_id_to_big_value_tmp_93be2_24.get_m31(0);
                *row[73] = op1_limb_0_col73;
                let op1_limb_1_col74 = memory_id_to_big_value_tmp_93be2_24.get_m31(1);
                *row[74] = op1_limb_1_col74;
                let op1_limb_2_col75 = memory_id_to_big_value_tmp_93be2_24.get_m31(2);
                *row[75] = op1_limb_2_col75;
                let op1_limb_3_col76 = memory_id_to_big_value_tmp_93be2_24.get_m31(3);
                *row[76] = op1_limb_3_col76;
                let op1_limb_4_col77 = memory_id_to_big_value_tmp_93be2_24.get_m31(4);
                *row[77] = op1_limb_4_col77;
                let op1_limb_5_col78 = memory_id_to_big_value_tmp_93be2_24.get_m31(5);
                *row[78] = op1_limb_5_col78;
                let op1_limb_6_col79 = memory_id_to_big_value_tmp_93be2_24.get_m31(6);
                *row[79] = op1_limb_6_col79;
                let op1_limb_7_col80 = memory_id_to_big_value_tmp_93be2_24.get_m31(7);
                *row[80] = op1_limb_7_col80;
                let op1_limb_8_col81 = memory_id_to_big_value_tmp_93be2_24.get_m31(8);
                *row[81] = op1_limb_8_col81;
                let op1_limb_9_col82 = memory_id_to_big_value_tmp_93be2_24.get_m31(9);
                *row[82] = op1_limb_9_col82;
                let op1_limb_10_col83 = memory_id_to_big_value_tmp_93be2_24.get_m31(10);
                *row[83] = op1_limb_10_col83;
                let op1_limb_11_col84 = memory_id_to_big_value_tmp_93be2_24.get_m31(11);
                *row[84] = op1_limb_11_col84;
                let op1_limb_12_col85 = memory_id_to_big_value_tmp_93be2_24.get_m31(12);
                *row[85] = op1_limb_12_col85;
                let op1_limb_13_col86 = memory_id_to_big_value_tmp_93be2_24.get_m31(13);
                *row[86] = op1_limb_13_col86;
                let op1_limb_14_col87 = memory_id_to_big_value_tmp_93be2_24.get_m31(14);
                *row[87] = op1_limb_14_col87;
                let op1_limb_15_col88 = memory_id_to_big_value_tmp_93be2_24.get_m31(15);
                *row[88] = op1_limb_15_col88;
                let op1_limb_16_col89 = memory_id_to_big_value_tmp_93be2_24.get_m31(16);
                *row[89] = op1_limb_16_col89;
                let op1_limb_17_col90 = memory_id_to_big_value_tmp_93be2_24.get_m31(17);
                *row[90] = op1_limb_17_col90;
                let op1_limb_18_col91 = memory_id_to_big_value_tmp_93be2_24.get_m31(18);
                *row[91] = op1_limb_18_col91;
                let op1_limb_19_col92 = memory_id_to_big_value_tmp_93be2_24.get_m31(19);
                *row[92] = op1_limb_19_col92;
                let op1_limb_20_col93 = memory_id_to_big_value_tmp_93be2_24.get_m31(20);
                *row[93] = op1_limb_20_col93;
                let op1_limb_21_col94 = memory_id_to_big_value_tmp_93be2_24.get_m31(21);
                *row[94] = op1_limb_21_col94;
                let op1_limb_22_col95 = memory_id_to_big_value_tmp_93be2_24.get_m31(22);
                *row[95] = op1_limb_22_col95;
                let op1_limb_23_col96 = memory_id_to_big_value_tmp_93be2_24.get_m31(23);
                *row[96] = op1_limb_23_col96;
                let op1_limb_24_col97 = memory_id_to_big_value_tmp_93be2_24.get_m31(24);
                *row[97] = op1_limb_24_col97;
                let op1_limb_25_col98 = memory_id_to_big_value_tmp_93be2_24.get_m31(25);
                *row[98] = op1_limb_25_col98;
                let op1_limb_26_col99 = memory_id_to_big_value_tmp_93be2_24.get_m31(26);
                *row[99] = op1_limb_26_col99;
                let op1_limb_27_col100 = memory_id_to_big_value_tmp_93be2_24.get_m31(27);
                *row[100] = op1_limb_27_col100;
                *sub_component_inputs.memory_id_to_big[2] = op1_id_col72;
                *lookup_data.memory_id_to_big_6 = [
                    M31_1662111297,
                    op1_id_col72,
                    op1_limb_0_col73,
                    op1_limb_1_col74,
                    op1_limb_2_col75,
                    op1_limb_3_col76,
                    op1_limb_4_col77,
                    op1_limb_5_col78,
                    op1_limb_6_col79,
                    op1_limb_7_col80,
                    op1_limb_8_col81,
                    op1_limb_9_col82,
                    op1_limb_10_col83,
                    op1_limb_11_col84,
                    op1_limb_12_col85,
                    op1_limb_13_col86,
                    op1_limb_14_col87,
                    op1_limb_15_col88,
                    op1_limb_16_col89,
                    op1_limb_17_col90,
                    op1_limb_18_col91,
                    op1_limb_19_col92,
                    op1_limb_20_col93,
                    op1_limb_21_col94,
                    op1_limb_22_col95,
                    op1_limb_23_col96,
                    op1_limb_24_col97,
                    op1_limb_25_col98,
                    op1_limb_26_col99,
                    op1_limb_27_col100,
                ];
                let read_positive_known_id_num_bits_252_output_tmp_93be2_25 =
                    PackedFelt252::from_limbs([
                        op1_limb_0_col73,
                        op1_limb_1_col74,
                        op1_limb_2_col75,
                        op1_limb_3_col76,
                        op1_limb_4_col77,
                        op1_limb_5_col78,
                        op1_limb_6_col79,
                        op1_limb_7_col80,
                        op1_limb_8_col81,
                        op1_limb_9_col82,
                        op1_limb_10_col83,
                        op1_limb_11_col84,
                        op1_limb_12_col85,
                        op1_limb_13_col86,
                        op1_limb_14_col87,
                        op1_limb_15_col88,
                        op1_limb_16_col89,
                        op1_limb_17_col90,
                        op1_limb_18_col91,
                        op1_limb_19_col92,
                        op1_limb_20_col93,
                        op1_limb_21_col94,
                        op1_limb_22_col95,
                        op1_limb_23_col96,
                        op1_limb_24_col97,
                        op1_limb_25_col98,
                        op1_limb_26_col99,
                        op1_limb_27_col100,
                    ]);

                let read_positive_num_bits_252_output_tmp_93be2_26 = (
                    read_positive_known_id_num_bits_252_output_tmp_93be2_25,
                    op1_id_col72,
                );

                // Verify Mul 252.

                // Double Karatsuba F 0 Fc 6.

                // Single Karatsuba N 7.

                let z0_tmp_93be2_27 = [
                    ((op0_limb_0_col44) * (op1_limb_0_col73)),
                    (((op0_limb_0_col44) * (op1_limb_1_col74))
                        + ((op0_limb_1_col45) * (op1_limb_0_col73))),
                    ((((op0_limb_0_col44) * (op1_limb_2_col75))
                        + ((op0_limb_1_col45) * (op1_limb_1_col74)))
                        + ((op0_limb_2_col46) * (op1_limb_0_col73))),
                    (((((op0_limb_0_col44) * (op1_limb_3_col76))
                        + ((op0_limb_1_col45) * (op1_limb_2_col75)))
                        + ((op0_limb_2_col46) * (op1_limb_1_col74)))
                        + ((op0_limb_3_col47) * (op1_limb_0_col73))),
                    ((((((op0_limb_0_col44) * (op1_limb_4_col77))
                        + ((op0_limb_1_col45) * (op1_limb_3_col76)))
                        + ((op0_limb_2_col46) * (op1_limb_2_col75)))
                        + ((op0_limb_3_col47) * (op1_limb_1_col74)))
                        + ((op0_limb_4_col48) * (op1_limb_0_col73))),
                    (((((((op0_limb_0_col44) * (op1_limb_5_col78))
                        + ((op0_limb_1_col45) * (op1_limb_4_col77)))
                        + ((op0_limb_2_col46) * (op1_limb_3_col76)))
                        + ((op0_limb_3_col47) * (op1_limb_2_col75)))
                        + ((op0_limb_4_col48) * (op1_limb_1_col74)))
                        + ((op0_limb_5_col49) * (op1_limb_0_col73))),
                    ((((((((op0_limb_0_col44) * (op1_limb_6_col79))
                        + ((op0_limb_1_col45) * (op1_limb_5_col78)))
                        + ((op0_limb_2_col46) * (op1_limb_4_col77)))
                        + ((op0_limb_3_col47) * (op1_limb_3_col76)))
                        + ((op0_limb_4_col48) * (op1_limb_2_col75)))
                        + ((op0_limb_5_col49) * (op1_limb_1_col74)))
                        + ((op0_limb_6_col50) * (op1_limb_0_col73))),
                    (((((((op0_limb_1_col45) * (op1_limb_6_col79))
                        + ((op0_limb_2_col46) * (op1_limb_5_col78)))
                        + ((op0_limb_3_col47) * (op1_limb_4_col77)))
                        + ((op0_limb_4_col48) * (op1_limb_3_col76)))
                        + ((op0_limb_5_col49) * (op1_limb_2_col75)))
                        + ((op0_limb_6_col50) * (op1_limb_1_col74))),
                    ((((((op0_limb_2_col46) * (op1_limb_6_col79))
                        + ((op0_limb_3_col47) * (op1_limb_5_col78)))
                        + ((op0_limb_4_col48) * (op1_limb_4_col77)))
                        + ((op0_limb_5_col49) * (op1_limb_3_col76)))
                        + ((op0_limb_6_col50) * (op1_limb_2_col75))),
                    (((((op0_limb_3_col47) * (op1_limb_6_col79))
                        + ((op0_limb_4_col48) * (op1_limb_5_col78)))
                        + ((op0_limb_5_col49) * (op1_limb_4_col77)))
                        + ((op0_limb_6_col50) * (op1_limb_3_col76))),
                    ((((op0_limb_4_col48) * (op1_limb_6_col79))
                        + ((op0_limb_5_col49) * (op1_limb_5_col78)))
                        + ((op0_limb_6_col50) * (op1_limb_4_col77))),
                    (((op0_limb_5_col49) * (op1_limb_6_col79))
                        + ((op0_limb_6_col50) * (op1_limb_5_col78))),
                    ((op0_limb_6_col50) * (op1_limb_6_col79)),
                ];
                let z2_tmp_93be2_28 = [
                    ((op0_limb_7_col51) * (op1_limb_7_col80)),
                    (((op0_limb_7_col51) * (op1_limb_8_col81))
                        + ((op0_limb_8_col52) * (op1_limb_7_col80))),
                    ((((op0_limb_7_col51) * (op1_limb_9_col82))
                        + ((op0_limb_8_col52) * (op1_limb_8_col81)))
                        + ((op0_limb_9_col53) * (op1_limb_7_col80))),
                    (((((op0_limb_7_col51) * (op1_limb_10_col83))
                        + ((op0_limb_8_col52) * (op1_limb_9_col82)))
                        + ((op0_limb_9_col53) * (op1_limb_8_col81)))
                        + ((op0_limb_10_col54) * (op1_limb_7_col80))),
                    ((((((op0_limb_7_col51) * (op1_limb_11_col84))
                        + ((op0_limb_8_col52) * (op1_limb_10_col83)))
                        + ((op0_limb_9_col53) * (op1_limb_9_col82)))
                        + ((op0_limb_10_col54) * (op1_limb_8_col81)))
                        + ((op0_limb_11_col55) * (op1_limb_7_col80))),
                    (((((((op0_limb_7_col51) * (op1_limb_12_col85))
                        + ((op0_limb_8_col52) * (op1_limb_11_col84)))
                        + ((op0_limb_9_col53) * (op1_limb_10_col83)))
                        + ((op0_limb_10_col54) * (op1_limb_9_col82)))
                        + ((op0_limb_11_col55) * (op1_limb_8_col81)))
                        + ((op0_limb_12_col56) * (op1_limb_7_col80))),
                    ((((((((op0_limb_7_col51) * (op1_limb_13_col86))
                        + ((op0_limb_8_col52) * (op1_limb_12_col85)))
                        + ((op0_limb_9_col53) * (op1_limb_11_col84)))
                        + ((op0_limb_10_col54) * (op1_limb_10_col83)))
                        + ((op0_limb_11_col55) * (op1_limb_9_col82)))
                        + ((op0_limb_12_col56) * (op1_limb_8_col81)))
                        + ((op0_limb_13_col57) * (op1_limb_7_col80))),
                    (((((((op0_limb_8_col52) * (op1_limb_13_col86))
                        + ((op0_limb_9_col53) * (op1_limb_12_col85)))
                        + ((op0_limb_10_col54) * (op1_limb_11_col84)))
                        + ((op0_limb_11_col55) * (op1_limb_10_col83)))
                        + ((op0_limb_12_col56) * (op1_limb_9_col82)))
                        + ((op0_limb_13_col57) * (op1_limb_8_col81))),
                    ((((((op0_limb_9_col53) * (op1_limb_13_col86))
                        + ((op0_limb_10_col54) * (op1_limb_12_col85)))
                        + ((op0_limb_11_col55) * (op1_limb_11_col84)))
                        + ((op0_limb_12_col56) * (op1_limb_10_col83)))
                        + ((op0_limb_13_col57) * (op1_limb_9_col82))),
                    (((((op0_limb_10_col54) * (op1_limb_13_col86))
                        + ((op0_limb_11_col55) * (op1_limb_12_col85)))
                        + ((op0_limb_12_col56) * (op1_limb_11_col84)))
                        + ((op0_limb_13_col57) * (op1_limb_10_col83))),
                    ((((op0_limb_11_col55) * (op1_limb_13_col86))
                        + ((op0_limb_12_col56) * (op1_limb_12_col85)))
                        + ((op0_limb_13_col57) * (op1_limb_11_col84))),
                    (((op0_limb_12_col56) * (op1_limb_13_col86))
                        + ((op0_limb_13_col57) * (op1_limb_12_col85))),
                    ((op0_limb_13_col57) * (op1_limb_13_col86)),
                ];
                let x_sum_tmp_93be2_29 = [
                    ((op0_limb_0_col44) + (op0_limb_7_col51)),
                    ((op0_limb_1_col45) + (op0_limb_8_col52)),
                    ((op0_limb_2_col46) + (op0_limb_9_col53)),
                    ((op0_limb_3_col47) + (op0_limb_10_col54)),
                    ((op0_limb_4_col48) + (op0_limb_11_col55)),
                    ((op0_limb_5_col49) + (op0_limb_12_col56)),
                    ((op0_limb_6_col50) + (op0_limb_13_col57)),
                ];
                let y_sum_tmp_93be2_30 = [
                    ((op1_limb_0_col73) + (op1_limb_7_col80)),
                    ((op1_limb_1_col74) + (op1_limb_8_col81)),
                    ((op1_limb_2_col75) + (op1_limb_9_col82)),
                    ((op1_limb_3_col76) + (op1_limb_10_col83)),
                    ((op1_limb_4_col77) + (op1_limb_11_col84)),
                    ((op1_limb_5_col78) + (op1_limb_12_col85)),
                    ((op1_limb_6_col79) + (op1_limb_13_col86)),
                ];
                let single_karatsuba_n_7_output_tmp_93be2_31 = [
                    z0_tmp_93be2_27[0],
                    z0_tmp_93be2_27[1],
                    z0_tmp_93be2_27[2],
                    z0_tmp_93be2_27[3],
                    z0_tmp_93be2_27[4],
                    z0_tmp_93be2_27[5],
                    z0_tmp_93be2_27[6],
                    ((z0_tmp_93be2_27[7])
                        + ((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[0]))
                            - (z0_tmp_93be2_27[0]))
                            - (z2_tmp_93be2_28[0]))),
                    ((z0_tmp_93be2_27[8])
                        + (((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[1]))
                            + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[0])))
                            - (z0_tmp_93be2_27[1]))
                            - (z2_tmp_93be2_28[1]))),
                    ((z0_tmp_93be2_27[9])
                        + ((((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[2]))
                            + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[1])))
                            + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[0])))
                            - (z0_tmp_93be2_27[2]))
                            - (z2_tmp_93be2_28[2]))),
                    ((z0_tmp_93be2_27[10])
                        + (((((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[3]))
                            + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[2])))
                            + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[1])))
                            + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[0])))
                            - (z0_tmp_93be2_27[3]))
                            - (z2_tmp_93be2_28[3]))),
                    ((z0_tmp_93be2_27[11])
                        + ((((((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[4]))
                            + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[3])))
                            + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[2])))
                            + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[1])))
                            + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[0])))
                            - (z0_tmp_93be2_27[4]))
                            - (z2_tmp_93be2_28[4]))),
                    ((z0_tmp_93be2_27[12])
                        + (((((((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[5]))
                            + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[4])))
                            + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[3])))
                            + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[2])))
                            + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[1])))
                            + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[0])))
                            - (z0_tmp_93be2_27[5]))
                            - (z2_tmp_93be2_28[5]))),
                    ((((((((((x_sum_tmp_93be2_29[0]) * (y_sum_tmp_93be2_30[6]))
                        + ((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[5])))
                        + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[4])))
                        + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[3])))
                        + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[2])))
                        + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[1])))
                        + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[0])))
                        - (z0_tmp_93be2_27[6]))
                        - (z2_tmp_93be2_28[6])),
                    ((z2_tmp_93be2_28[0])
                        + (((((((((x_sum_tmp_93be2_29[1]) * (y_sum_tmp_93be2_30[6]))
                            + ((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[5])))
                            + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[4])))
                            + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[3])))
                            + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[2])))
                            + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[1])))
                            - (z0_tmp_93be2_27[7]))
                            - (z2_tmp_93be2_28[7]))),
                    ((z2_tmp_93be2_28[1])
                        + ((((((((x_sum_tmp_93be2_29[2]) * (y_sum_tmp_93be2_30[6]))
                            + ((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[5])))
                            + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[4])))
                            + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[3])))
                            + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[2])))
                            - (z0_tmp_93be2_27[8]))
                            - (z2_tmp_93be2_28[8]))),
                    ((z2_tmp_93be2_28[2])
                        + (((((((x_sum_tmp_93be2_29[3]) * (y_sum_tmp_93be2_30[6]))
                            + ((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[5])))
                            + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[4])))
                            + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[3])))
                            - (z0_tmp_93be2_27[9]))
                            - (z2_tmp_93be2_28[9]))),
                    ((z2_tmp_93be2_28[3])
                        + ((((((x_sum_tmp_93be2_29[4]) * (y_sum_tmp_93be2_30[6]))
                            + ((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[5])))
                            + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[4])))
                            - (z0_tmp_93be2_27[10]))
                            - (z2_tmp_93be2_28[10]))),
                    ((z2_tmp_93be2_28[4])
                        + (((((x_sum_tmp_93be2_29[5]) * (y_sum_tmp_93be2_30[6]))
                            + ((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[5])))
                            - (z0_tmp_93be2_27[11]))
                            - (z2_tmp_93be2_28[11]))),
                    ((z2_tmp_93be2_28[5])
                        + ((((x_sum_tmp_93be2_29[6]) * (y_sum_tmp_93be2_30[6]))
                            - (z0_tmp_93be2_27[12]))
                            - (z2_tmp_93be2_28[12]))),
                    z2_tmp_93be2_28[6],
                    z2_tmp_93be2_28[7],
                    z2_tmp_93be2_28[8],
                    z2_tmp_93be2_28[9],
                    z2_tmp_93be2_28[10],
                    z2_tmp_93be2_28[11],
                    z2_tmp_93be2_28[12],
                ];

                // Single Karatsuba N 7.

                let z0_tmp_93be2_32 = [
                    ((op0_limb_14_col58) * (op1_limb_14_col87)),
                    (((op0_limb_14_col58) * (op1_limb_15_col88))
                        + ((op0_limb_15_col59) * (op1_limb_14_col87))),
                    ((((op0_limb_14_col58) * (op1_limb_16_col89))
                        + ((op0_limb_15_col59) * (op1_limb_15_col88)))
                        + ((op0_limb_16_col60) * (op1_limb_14_col87))),
                    (((((op0_limb_14_col58) * (op1_limb_17_col90))
                        + ((op0_limb_15_col59) * (op1_limb_16_col89)))
                        + ((op0_limb_16_col60) * (op1_limb_15_col88)))
                        + ((op0_limb_17_col61) * (op1_limb_14_col87))),
                    ((((((op0_limb_14_col58) * (op1_limb_18_col91))
                        + ((op0_limb_15_col59) * (op1_limb_17_col90)))
                        + ((op0_limb_16_col60) * (op1_limb_16_col89)))
                        + ((op0_limb_17_col61) * (op1_limb_15_col88)))
                        + ((op0_limb_18_col62) * (op1_limb_14_col87))),
                    (((((((op0_limb_14_col58) * (op1_limb_19_col92))
                        + ((op0_limb_15_col59) * (op1_limb_18_col91)))
                        + ((op0_limb_16_col60) * (op1_limb_17_col90)))
                        + ((op0_limb_17_col61) * (op1_limb_16_col89)))
                        + ((op0_limb_18_col62) * (op1_limb_15_col88)))
                        + ((op0_limb_19_col63) * (op1_limb_14_col87))),
                    ((((((((op0_limb_14_col58) * (op1_limb_20_col93))
                        + ((op0_limb_15_col59) * (op1_limb_19_col92)))
                        + ((op0_limb_16_col60) * (op1_limb_18_col91)))
                        + ((op0_limb_17_col61) * (op1_limb_17_col90)))
                        + ((op0_limb_18_col62) * (op1_limb_16_col89)))
                        + ((op0_limb_19_col63) * (op1_limb_15_col88)))
                        + ((op0_limb_20_col64) * (op1_limb_14_col87))),
                    (((((((op0_limb_15_col59) * (op1_limb_20_col93))
                        + ((op0_limb_16_col60) * (op1_limb_19_col92)))
                        + ((op0_limb_17_col61) * (op1_limb_18_col91)))
                        + ((op0_limb_18_col62) * (op1_limb_17_col90)))
                        + ((op0_limb_19_col63) * (op1_limb_16_col89)))
                        + ((op0_limb_20_col64) * (op1_limb_15_col88))),
                    ((((((op0_limb_16_col60) * (op1_limb_20_col93))
                        + ((op0_limb_17_col61) * (op1_limb_19_col92)))
                        + ((op0_limb_18_col62) * (op1_limb_18_col91)))
                        + ((op0_limb_19_col63) * (op1_limb_17_col90)))
                        + ((op0_limb_20_col64) * (op1_limb_16_col89))),
                    (((((op0_limb_17_col61) * (op1_limb_20_col93))
                        + ((op0_limb_18_col62) * (op1_limb_19_col92)))
                        + ((op0_limb_19_col63) * (op1_limb_18_col91)))
                        + ((op0_limb_20_col64) * (op1_limb_17_col90))),
                    ((((op0_limb_18_col62) * (op1_limb_20_col93))
                        + ((op0_limb_19_col63) * (op1_limb_19_col92)))
                        + ((op0_limb_20_col64) * (op1_limb_18_col91))),
                    (((op0_limb_19_col63) * (op1_limb_20_col93))
                        + ((op0_limb_20_col64) * (op1_limb_19_col92))),
                    ((op0_limb_20_col64) * (op1_limb_20_col93)),
                ];
                let z2_tmp_93be2_33 = [
                    ((op0_limb_21_col65) * (op1_limb_21_col94)),
                    (((op0_limb_21_col65) * (op1_limb_22_col95))
                        + ((op0_limb_22_col66) * (op1_limb_21_col94))),
                    ((((op0_limb_21_col65) * (op1_limb_23_col96))
                        + ((op0_limb_22_col66) * (op1_limb_22_col95)))
                        + ((op0_limb_23_col67) * (op1_limb_21_col94))),
                    (((((op0_limb_21_col65) * (op1_limb_24_col97))
                        + ((op0_limb_22_col66) * (op1_limb_23_col96)))
                        + ((op0_limb_23_col67) * (op1_limb_22_col95)))
                        + ((op0_limb_24_col68) * (op1_limb_21_col94))),
                    ((((((op0_limb_21_col65) * (op1_limb_25_col98))
                        + ((op0_limb_22_col66) * (op1_limb_24_col97)))
                        + ((op0_limb_23_col67) * (op1_limb_23_col96)))
                        + ((op0_limb_24_col68) * (op1_limb_22_col95)))
                        + ((op0_limb_25_col69) * (op1_limb_21_col94))),
                    (((((((op0_limb_21_col65) * (op1_limb_26_col99))
                        + ((op0_limb_22_col66) * (op1_limb_25_col98)))
                        + ((op0_limb_23_col67) * (op1_limb_24_col97)))
                        + ((op0_limb_24_col68) * (op1_limb_23_col96)))
                        + ((op0_limb_25_col69) * (op1_limb_22_col95)))
                        + ((op0_limb_26_col70) * (op1_limb_21_col94))),
                    ((((((((op0_limb_21_col65) * (op1_limb_27_col100))
                        + ((op0_limb_22_col66) * (op1_limb_26_col99)))
                        + ((op0_limb_23_col67) * (op1_limb_25_col98)))
                        + ((op0_limb_24_col68) * (op1_limb_24_col97)))
                        + ((op0_limb_25_col69) * (op1_limb_23_col96)))
                        + ((op0_limb_26_col70) * (op1_limb_22_col95)))
                        + ((op0_limb_27_col71) * (op1_limb_21_col94))),
                    (((((((op0_limb_22_col66) * (op1_limb_27_col100))
                        + ((op0_limb_23_col67) * (op1_limb_26_col99)))
                        + ((op0_limb_24_col68) * (op1_limb_25_col98)))
                        + ((op0_limb_25_col69) * (op1_limb_24_col97)))
                        + ((op0_limb_26_col70) * (op1_limb_23_col96)))
                        + ((op0_limb_27_col71) * (op1_limb_22_col95))),
                    ((((((op0_limb_23_col67) * (op1_limb_27_col100))
                        + ((op0_limb_24_col68) * (op1_limb_26_col99)))
                        + ((op0_limb_25_col69) * (op1_limb_25_col98)))
                        + ((op0_limb_26_col70) * (op1_limb_24_col97)))
                        + ((op0_limb_27_col71) * (op1_limb_23_col96))),
                    (((((op0_limb_24_col68) * (op1_limb_27_col100))
                        + ((op0_limb_25_col69) * (op1_limb_26_col99)))
                        + ((op0_limb_26_col70) * (op1_limb_25_col98)))
                        + ((op0_limb_27_col71) * (op1_limb_24_col97))),
                    ((((op0_limb_25_col69) * (op1_limb_27_col100))
                        + ((op0_limb_26_col70) * (op1_limb_26_col99)))
                        + ((op0_limb_27_col71) * (op1_limb_25_col98))),
                    (((op0_limb_26_col70) * (op1_limb_27_col100))
                        + ((op0_limb_27_col71) * (op1_limb_26_col99))),
                    ((op0_limb_27_col71) * (op1_limb_27_col100)),
                ];
                let x_sum_tmp_93be2_34 = [
                    ((op0_limb_14_col58) + (op0_limb_21_col65)),
                    ((op0_limb_15_col59) + (op0_limb_22_col66)),
                    ((op0_limb_16_col60) + (op0_limb_23_col67)),
                    ((op0_limb_17_col61) + (op0_limb_24_col68)),
                    ((op0_limb_18_col62) + (op0_limb_25_col69)),
                    ((op0_limb_19_col63) + (op0_limb_26_col70)),
                    ((op0_limb_20_col64) + (op0_limb_27_col71)),
                ];
                let y_sum_tmp_93be2_35 = [
                    ((op1_limb_14_col87) + (op1_limb_21_col94)),
                    ((op1_limb_15_col88) + (op1_limb_22_col95)),
                    ((op1_limb_16_col89) + (op1_limb_23_col96)),
                    ((op1_limb_17_col90) + (op1_limb_24_col97)),
                    ((op1_limb_18_col91) + (op1_limb_25_col98)),
                    ((op1_limb_19_col92) + (op1_limb_26_col99)),
                    ((op1_limb_20_col93) + (op1_limb_27_col100)),
                ];
                let single_karatsuba_n_7_output_tmp_93be2_36 = [
                    z0_tmp_93be2_32[0],
                    z0_tmp_93be2_32[1],
                    z0_tmp_93be2_32[2],
                    z0_tmp_93be2_32[3],
                    z0_tmp_93be2_32[4],
                    z0_tmp_93be2_32[5],
                    z0_tmp_93be2_32[6],
                    ((z0_tmp_93be2_32[7])
                        + ((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[0]))
                            - (z0_tmp_93be2_32[0]))
                            - (z2_tmp_93be2_33[0]))),
                    ((z0_tmp_93be2_32[8])
                        + (((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[1]))
                            + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[0])))
                            - (z0_tmp_93be2_32[1]))
                            - (z2_tmp_93be2_33[1]))),
                    ((z0_tmp_93be2_32[9])
                        + ((((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[2]))
                            + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[1])))
                            + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[0])))
                            - (z0_tmp_93be2_32[2]))
                            - (z2_tmp_93be2_33[2]))),
                    ((z0_tmp_93be2_32[10])
                        + (((((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[3]))
                            + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[2])))
                            + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[1])))
                            + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[0])))
                            - (z0_tmp_93be2_32[3]))
                            - (z2_tmp_93be2_33[3]))),
                    ((z0_tmp_93be2_32[11])
                        + ((((((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[4]))
                            + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[3])))
                            + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[2])))
                            + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[1])))
                            + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[0])))
                            - (z0_tmp_93be2_32[4]))
                            - (z2_tmp_93be2_33[4]))),
                    ((z0_tmp_93be2_32[12])
                        + (((((((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[5]))
                            + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[4])))
                            + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[3])))
                            + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[2])))
                            + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[1])))
                            + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[0])))
                            - (z0_tmp_93be2_32[5]))
                            - (z2_tmp_93be2_33[5]))),
                    ((((((((((x_sum_tmp_93be2_34[0]) * (y_sum_tmp_93be2_35[6]))
                        + ((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[5])))
                        + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[4])))
                        + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[3])))
                        + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[2])))
                        + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[1])))
                        + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[0])))
                        - (z0_tmp_93be2_32[6]))
                        - (z2_tmp_93be2_33[6])),
                    ((z2_tmp_93be2_33[0])
                        + (((((((((x_sum_tmp_93be2_34[1]) * (y_sum_tmp_93be2_35[6]))
                            + ((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[5])))
                            + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[4])))
                            + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[3])))
                            + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[2])))
                            + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[1])))
                            - (z0_tmp_93be2_32[7]))
                            - (z2_tmp_93be2_33[7]))),
                    ((z2_tmp_93be2_33[1])
                        + ((((((((x_sum_tmp_93be2_34[2]) * (y_sum_tmp_93be2_35[6]))
                            + ((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[5])))
                            + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[4])))
                            + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[3])))
                            + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[2])))
                            - (z0_tmp_93be2_32[8]))
                            - (z2_tmp_93be2_33[8]))),
                    ((z2_tmp_93be2_33[2])
                        + (((((((x_sum_tmp_93be2_34[3]) * (y_sum_tmp_93be2_35[6]))
                            + ((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[5])))
                            + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[4])))
                            + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[3])))
                            - (z0_tmp_93be2_32[9]))
                            - (z2_tmp_93be2_33[9]))),
                    ((z2_tmp_93be2_33[3])
                        + ((((((x_sum_tmp_93be2_34[4]) * (y_sum_tmp_93be2_35[6]))
                            + ((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[5])))
                            + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[4])))
                            - (z0_tmp_93be2_32[10]))
                            - (z2_tmp_93be2_33[10]))),
                    ((z2_tmp_93be2_33[4])
                        + (((((x_sum_tmp_93be2_34[5]) * (y_sum_tmp_93be2_35[6]))
                            + ((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[5])))
                            - (z0_tmp_93be2_32[11]))
                            - (z2_tmp_93be2_33[11]))),
                    ((z2_tmp_93be2_33[5])
                        + ((((x_sum_tmp_93be2_34[6]) * (y_sum_tmp_93be2_35[6]))
                            - (z0_tmp_93be2_32[12]))
                            - (z2_tmp_93be2_33[12]))),
                    z2_tmp_93be2_33[6],
                    z2_tmp_93be2_33[7],
                    z2_tmp_93be2_33[8],
                    z2_tmp_93be2_33[9],
                    z2_tmp_93be2_33[10],
                    z2_tmp_93be2_33[11],
                    z2_tmp_93be2_33[12],
                ];

                let x_sum_tmp_93be2_37 = [
                    ((op0_limb_0_col44) + (op0_limb_14_col58)),
                    ((op0_limb_1_col45) + (op0_limb_15_col59)),
                    ((op0_limb_2_col46) + (op0_limb_16_col60)),
                    ((op0_limb_3_col47) + (op0_limb_17_col61)),
                    ((op0_limb_4_col48) + (op0_limb_18_col62)),
                    ((op0_limb_5_col49) + (op0_limb_19_col63)),
                    ((op0_limb_6_col50) + (op0_limb_20_col64)),
                    ((op0_limb_7_col51) + (op0_limb_21_col65)),
                    ((op0_limb_8_col52) + (op0_limb_22_col66)),
                    ((op0_limb_9_col53) + (op0_limb_23_col67)),
                    ((op0_limb_10_col54) + (op0_limb_24_col68)),
                    ((op0_limb_11_col55) + (op0_limb_25_col69)),
                    ((op0_limb_12_col56) + (op0_limb_26_col70)),
                    ((op0_limb_13_col57) + (op0_limb_27_col71)),
                ];
                let y_sum_tmp_93be2_38 = [
                    ((op1_limb_0_col73) + (op1_limb_14_col87)),
                    ((op1_limb_1_col74) + (op1_limb_15_col88)),
                    ((op1_limb_2_col75) + (op1_limb_16_col89)),
                    ((op1_limb_3_col76) + (op1_limb_17_col90)),
                    ((op1_limb_4_col77) + (op1_limb_18_col91)),
                    ((op1_limb_5_col78) + (op1_limb_19_col92)),
                    ((op1_limb_6_col79) + (op1_limb_20_col93)),
                    ((op1_limb_7_col80) + (op1_limb_21_col94)),
                    ((op1_limb_8_col81) + (op1_limb_22_col95)),
                    ((op1_limb_9_col82) + (op1_limb_23_col96)),
                    ((op1_limb_10_col83) + (op1_limb_24_col97)),
                    ((op1_limb_11_col84) + (op1_limb_25_col98)),
                    ((op1_limb_12_col85) + (op1_limb_26_col99)),
                    ((op1_limb_13_col86) + (op1_limb_27_col100)),
                ];

                // Single Karatsuba N 7.

                let z0_tmp_93be2_39 = [
                    ((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[0])),
                    (((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[1]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[0]))),
                    ((((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[2]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[1])))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[0]))),
                    (((((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[3]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[2])))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[1])))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[0]))),
                    ((((((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[4]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[3])))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[2])))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[1])))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[0]))),
                    (((((((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[5]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[4])))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[3])))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[2])))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[1])))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[0]))),
                    ((((((((x_sum_tmp_93be2_37[0]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[5])))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[4])))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[3])))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[2])))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[1])))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[0]))),
                    (((((((x_sum_tmp_93be2_37[1]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[5])))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[4])))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[3])))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[2])))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[1]))),
                    ((((((x_sum_tmp_93be2_37[2]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[5])))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[4])))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[3])))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[2]))),
                    (((((x_sum_tmp_93be2_37[3]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[5])))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[4])))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[3]))),
                    ((((x_sum_tmp_93be2_37[4]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[5])))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[4]))),
                    (((x_sum_tmp_93be2_37[5]) * (y_sum_tmp_93be2_38[6]))
                        + ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[5]))),
                    ((x_sum_tmp_93be2_37[6]) * (y_sum_tmp_93be2_38[6])),
                ];
                let z2_tmp_93be2_40 = [
                    ((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[7])),
                    (((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[8]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[7]))),
                    ((((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[9]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[8])))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[7]))),
                    (((((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[10]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[9])))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[8])))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[7]))),
                    ((((((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[11]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[10])))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[9])))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[8])))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[7]))),
                    (((((((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[12]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[11])))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[10])))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[9])))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[8])))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[7]))),
                    ((((((((x_sum_tmp_93be2_37[7]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[12])))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[11])))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[10])))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[9])))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[8])))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[7]))),
                    (((((((x_sum_tmp_93be2_37[8]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[12])))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[11])))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[10])))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[9])))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[8]))),
                    ((((((x_sum_tmp_93be2_37[9]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[12])))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[11])))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[10])))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[9]))),
                    (((((x_sum_tmp_93be2_37[10]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[12])))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[11])))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[10]))),
                    ((((x_sum_tmp_93be2_37[11]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[12])))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[11]))),
                    (((x_sum_tmp_93be2_37[12]) * (y_sum_tmp_93be2_38[13]))
                        + ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[12]))),
                    ((x_sum_tmp_93be2_37[13]) * (y_sum_tmp_93be2_38[13])),
                ];
                let x_sum_tmp_93be2_41 = [
                    ((x_sum_tmp_93be2_37[0]) + (x_sum_tmp_93be2_37[7])),
                    ((x_sum_tmp_93be2_37[1]) + (x_sum_tmp_93be2_37[8])),
                    ((x_sum_tmp_93be2_37[2]) + (x_sum_tmp_93be2_37[9])),
                    ((x_sum_tmp_93be2_37[3]) + (x_sum_tmp_93be2_37[10])),
                    ((x_sum_tmp_93be2_37[4]) + (x_sum_tmp_93be2_37[11])),
                    ((x_sum_tmp_93be2_37[5]) + (x_sum_tmp_93be2_37[12])),
                    ((x_sum_tmp_93be2_37[6]) + (x_sum_tmp_93be2_37[13])),
                ];
                let y_sum_tmp_93be2_42 = [
                    ((y_sum_tmp_93be2_38[0]) + (y_sum_tmp_93be2_38[7])),
                    ((y_sum_tmp_93be2_38[1]) + (y_sum_tmp_93be2_38[8])),
                    ((y_sum_tmp_93be2_38[2]) + (y_sum_tmp_93be2_38[9])),
                    ((y_sum_tmp_93be2_38[3]) + (y_sum_tmp_93be2_38[10])),
                    ((y_sum_tmp_93be2_38[4]) + (y_sum_tmp_93be2_38[11])),
                    ((y_sum_tmp_93be2_38[5]) + (y_sum_tmp_93be2_38[12])),
                    ((y_sum_tmp_93be2_38[6]) + (y_sum_tmp_93be2_38[13])),
                ];
                let single_karatsuba_n_7_output_tmp_93be2_43 = [
                    z0_tmp_93be2_39[0],
                    z0_tmp_93be2_39[1],
                    z0_tmp_93be2_39[2],
                    z0_tmp_93be2_39[3],
                    z0_tmp_93be2_39[4],
                    z0_tmp_93be2_39[5],
                    z0_tmp_93be2_39[6],
                    ((z0_tmp_93be2_39[7])
                        + ((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[0]))
                            - (z0_tmp_93be2_39[0]))
                            - (z2_tmp_93be2_40[0]))),
                    ((z0_tmp_93be2_39[8])
                        + (((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[1]))
                            + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[0])))
                            - (z0_tmp_93be2_39[1]))
                            - (z2_tmp_93be2_40[1]))),
                    ((z0_tmp_93be2_39[9])
                        + ((((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[2]))
                            + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[1])))
                            + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[0])))
                            - (z0_tmp_93be2_39[2]))
                            - (z2_tmp_93be2_40[2]))),
                    ((z0_tmp_93be2_39[10])
                        + (((((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[3]))
                            + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[2])))
                            + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[1])))
                            + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[0])))
                            - (z0_tmp_93be2_39[3]))
                            - (z2_tmp_93be2_40[3]))),
                    ((z0_tmp_93be2_39[11])
                        + ((((((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[4]))
                            + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[3])))
                            + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[2])))
                            + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[1])))
                            + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[0])))
                            - (z0_tmp_93be2_39[4]))
                            - (z2_tmp_93be2_40[4]))),
                    ((z0_tmp_93be2_39[12])
                        + (((((((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[5]))
                            + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[4])))
                            + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[3])))
                            + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[2])))
                            + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[1])))
                            + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[0])))
                            - (z0_tmp_93be2_39[5]))
                            - (z2_tmp_93be2_40[5]))),
                    ((((((((((x_sum_tmp_93be2_41[0]) * (y_sum_tmp_93be2_42[6]))
                        + ((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[5])))
                        + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[4])))
                        + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[3])))
                        + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[2])))
                        + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[1])))
                        + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[0])))
                        - (z0_tmp_93be2_39[6]))
                        - (z2_tmp_93be2_40[6])),
                    ((z2_tmp_93be2_40[0])
                        + (((((((((x_sum_tmp_93be2_41[1]) * (y_sum_tmp_93be2_42[6]))
                            + ((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[5])))
                            + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[4])))
                            + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[3])))
                            + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[2])))
                            + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[1])))
                            - (z0_tmp_93be2_39[7]))
                            - (z2_tmp_93be2_40[7]))),
                    ((z2_tmp_93be2_40[1])
                        + ((((((((x_sum_tmp_93be2_41[2]) * (y_sum_tmp_93be2_42[6]))
                            + ((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[5])))
                            + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[4])))
                            + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[3])))
                            + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[2])))
                            - (z0_tmp_93be2_39[8]))
                            - (z2_tmp_93be2_40[8]))),
                    ((z2_tmp_93be2_40[2])
                        + (((((((x_sum_tmp_93be2_41[3]) * (y_sum_tmp_93be2_42[6]))
                            + ((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[5])))
                            + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[4])))
                            + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[3])))
                            - (z0_tmp_93be2_39[9]))
                            - (z2_tmp_93be2_40[9]))),
                    ((z2_tmp_93be2_40[3])
                        + ((((((x_sum_tmp_93be2_41[4]) * (y_sum_tmp_93be2_42[6]))
                            + ((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[5])))
                            + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[4])))
                            - (z0_tmp_93be2_39[10]))
                            - (z2_tmp_93be2_40[10]))),
                    ((z2_tmp_93be2_40[4])
                        + (((((x_sum_tmp_93be2_41[5]) * (y_sum_tmp_93be2_42[6]))
                            + ((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[5])))
                            - (z0_tmp_93be2_39[11]))
                            - (z2_tmp_93be2_40[11]))),
                    ((z2_tmp_93be2_40[5])
                        + ((((x_sum_tmp_93be2_41[6]) * (y_sum_tmp_93be2_42[6]))
                            - (z0_tmp_93be2_39[12]))
                            - (z2_tmp_93be2_40[12]))),
                    z2_tmp_93be2_40[6],
                    z2_tmp_93be2_40[7],
                    z2_tmp_93be2_40[8],
                    z2_tmp_93be2_40[9],
                    z2_tmp_93be2_40[10],
                    z2_tmp_93be2_40[11],
                    z2_tmp_93be2_40[12],
                ];

                let double_karatsuba_f0fc6_output_tmp_93be2_44 = [
                    single_karatsuba_n_7_output_tmp_93be2_31[0],
                    single_karatsuba_n_7_output_tmp_93be2_31[1],
                    single_karatsuba_n_7_output_tmp_93be2_31[2],
                    single_karatsuba_n_7_output_tmp_93be2_31[3],
                    single_karatsuba_n_7_output_tmp_93be2_31[4],
                    single_karatsuba_n_7_output_tmp_93be2_31[5],
                    single_karatsuba_n_7_output_tmp_93be2_31[6],
                    single_karatsuba_n_7_output_tmp_93be2_31[7],
                    single_karatsuba_n_7_output_tmp_93be2_31[8],
                    single_karatsuba_n_7_output_tmp_93be2_31[9],
                    single_karatsuba_n_7_output_tmp_93be2_31[10],
                    single_karatsuba_n_7_output_tmp_93be2_31[11],
                    single_karatsuba_n_7_output_tmp_93be2_31[12],
                    single_karatsuba_n_7_output_tmp_93be2_31[13],
                    ((single_karatsuba_n_7_output_tmp_93be2_31[14])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[0])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[0]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[0]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[15])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[1])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[1]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[1]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[16])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[2])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[2]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[2]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[17])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[3])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[3]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[3]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[18])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[4])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[4]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[4]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[19])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[5])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[5]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[5]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[20])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[6])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[6]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[6]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[21])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[7])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[7]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[7]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[22])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[8])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[8]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[8]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[23])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[9])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[9]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[9]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[24])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[10])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[10]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[10]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[25])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[11])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[11]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[11]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_31[26])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[12])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[12]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[12]))),
                    (((single_karatsuba_n_7_output_tmp_93be2_43[13])
                        - (single_karatsuba_n_7_output_tmp_93be2_31[13]))
                        - (single_karatsuba_n_7_output_tmp_93be2_36[13])),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[0])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[14])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[14]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[14]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[1])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[15])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[15]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[15]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[2])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[16])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[16]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[16]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[3])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[17])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[17]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[17]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[4])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[18])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[18]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[18]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[5])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[19])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[19]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[19]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[6])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[20])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[20]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[20]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[7])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[21])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[21]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[21]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[8])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[22])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[22]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[22]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[9])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[23])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[23]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[23]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[10])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[24])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[24]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[24]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[11])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[25])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[25]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[25]))),
                    ((single_karatsuba_n_7_output_tmp_93be2_36[12])
                        + (((single_karatsuba_n_7_output_tmp_93be2_43[26])
                            - (single_karatsuba_n_7_output_tmp_93be2_31[26]))
                            - (single_karatsuba_n_7_output_tmp_93be2_36[26]))),
                    single_karatsuba_n_7_output_tmp_93be2_36[13],
                    single_karatsuba_n_7_output_tmp_93be2_36[14],
                    single_karatsuba_n_7_output_tmp_93be2_36[15],
                    single_karatsuba_n_7_output_tmp_93be2_36[16],
                    single_karatsuba_n_7_output_tmp_93be2_36[17],
                    single_karatsuba_n_7_output_tmp_93be2_36[18],
                    single_karatsuba_n_7_output_tmp_93be2_36[19],
                    single_karatsuba_n_7_output_tmp_93be2_36[20],
                    single_karatsuba_n_7_output_tmp_93be2_36[21],
                    single_karatsuba_n_7_output_tmp_93be2_36[22],
                    single_karatsuba_n_7_output_tmp_93be2_36[23],
                    single_karatsuba_n_7_output_tmp_93be2_36[24],
                    single_karatsuba_n_7_output_tmp_93be2_36[25],
                    single_karatsuba_n_7_output_tmp_93be2_36[26],
                ];

                let conv_tmp_93be2_45 = [
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[0]) - (dst_limb_0_col15)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[1]) - (dst_limb_1_col16)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[2]) - (dst_limb_2_col17)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[3]) - (dst_limb_3_col18)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[4]) - (dst_limb_4_col19)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[5]) - (dst_limb_5_col20)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[6]) - (dst_limb_6_col21)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[7]) - (dst_limb_7_col22)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[8]) - (dst_limb_8_col23)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[9]) - (dst_limb_9_col24)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[10]) - (dst_limb_10_col25)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[11]) - (dst_limb_11_col26)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[12]) - (dst_limb_12_col27)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[13]) - (dst_limb_13_col28)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[14]) - (dst_limb_14_col29)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[15]) - (dst_limb_15_col30)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[16]) - (dst_limb_16_col31)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[17]) - (dst_limb_17_col32)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[18]) - (dst_limb_18_col33)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[19]) - (dst_limb_19_col34)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[20]) - (dst_limb_20_col35)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[21]) - (dst_limb_21_col36)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[22]) - (dst_limb_22_col37)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[23]) - (dst_limb_23_col38)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[24]) - (dst_limb_24_col39)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[25]) - (dst_limb_25_col40)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[26]) - (dst_limb_26_col41)),
                    ((double_karatsuba_f0fc6_output_tmp_93be2_44[27]) - (dst_limb_27_col42)),
                    double_karatsuba_f0fc6_output_tmp_93be2_44[28],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[29],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[30],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[31],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[32],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[33],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[34],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[35],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[36],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[37],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[38],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[39],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[40],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[41],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[42],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[43],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[44],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[45],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[46],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[47],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[48],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[49],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[50],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[51],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[52],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[53],
                    double_karatsuba_f0fc6_output_tmp_93be2_44[54],
                ];
                let conv_mod_tmp_93be2_46 = [
                    ((((M31_32) * (conv_tmp_93be2_45[0])) - ((M31_4) * (conv_tmp_93be2_45[21])))
                        + ((M31_8) * (conv_tmp_93be2_45[49]))),
                    ((((conv_tmp_93be2_45[0]) + ((M31_32) * (conv_tmp_93be2_45[1])))
                        - ((M31_4) * (conv_tmp_93be2_45[22])))
                        + ((M31_8) * (conv_tmp_93be2_45[50]))),
                    ((((conv_tmp_93be2_45[1]) + ((M31_32) * (conv_tmp_93be2_45[2])))
                        - ((M31_4) * (conv_tmp_93be2_45[23])))
                        + ((M31_8) * (conv_tmp_93be2_45[51]))),
                    ((((conv_tmp_93be2_45[2]) + ((M31_32) * (conv_tmp_93be2_45[3])))
                        - ((M31_4) * (conv_tmp_93be2_45[24])))
                        + ((M31_8) * (conv_tmp_93be2_45[52]))),
                    ((((conv_tmp_93be2_45[3]) + ((M31_32) * (conv_tmp_93be2_45[4])))
                        - ((M31_4) * (conv_tmp_93be2_45[25])))
                        + ((M31_8) * (conv_tmp_93be2_45[53]))),
                    ((((conv_tmp_93be2_45[4]) + ((M31_32) * (conv_tmp_93be2_45[5])))
                        - ((M31_4) * (conv_tmp_93be2_45[26])))
                        + ((M31_8) * (conv_tmp_93be2_45[54]))),
                    (((conv_tmp_93be2_45[5]) + ((M31_32) * (conv_tmp_93be2_45[6])))
                        - ((M31_4) * (conv_tmp_93be2_45[27]))),
                    (((((M31_2) * (conv_tmp_93be2_45[0])) + (conv_tmp_93be2_45[6]))
                        + ((M31_32) * (conv_tmp_93be2_45[7])))
                        - ((M31_4) * (conv_tmp_93be2_45[28]))),
                    (((((M31_2) * (conv_tmp_93be2_45[1])) + (conv_tmp_93be2_45[7]))
                        + ((M31_32) * (conv_tmp_93be2_45[8])))
                        - ((M31_4) * (conv_tmp_93be2_45[29]))),
                    (((((M31_2) * (conv_tmp_93be2_45[2])) + (conv_tmp_93be2_45[8]))
                        + ((M31_32) * (conv_tmp_93be2_45[9])))
                        - ((M31_4) * (conv_tmp_93be2_45[30]))),
                    (((((M31_2) * (conv_tmp_93be2_45[3])) + (conv_tmp_93be2_45[9]))
                        + ((M31_32) * (conv_tmp_93be2_45[10])))
                        - ((M31_4) * (conv_tmp_93be2_45[31]))),
                    (((((M31_2) * (conv_tmp_93be2_45[4])) + (conv_tmp_93be2_45[10]))
                        + ((M31_32) * (conv_tmp_93be2_45[11])))
                        - ((M31_4) * (conv_tmp_93be2_45[32]))),
                    (((((M31_2) * (conv_tmp_93be2_45[5])) + (conv_tmp_93be2_45[11]))
                        + ((M31_32) * (conv_tmp_93be2_45[12])))
                        - ((M31_4) * (conv_tmp_93be2_45[33]))),
                    (((((M31_2) * (conv_tmp_93be2_45[6])) + (conv_tmp_93be2_45[12]))
                        + ((M31_32) * (conv_tmp_93be2_45[13])))
                        - ((M31_4) * (conv_tmp_93be2_45[34]))),
                    (((((M31_2) * (conv_tmp_93be2_45[7])) + (conv_tmp_93be2_45[13]))
                        + ((M31_32) * (conv_tmp_93be2_45[14])))
                        - ((M31_4) * (conv_tmp_93be2_45[35]))),
                    (((((M31_2) * (conv_tmp_93be2_45[8])) + (conv_tmp_93be2_45[14]))
                        + ((M31_32) * (conv_tmp_93be2_45[15])))
                        - ((M31_4) * (conv_tmp_93be2_45[36]))),
                    (((((M31_2) * (conv_tmp_93be2_45[9])) + (conv_tmp_93be2_45[15]))
                        + ((M31_32) * (conv_tmp_93be2_45[16])))
                        - ((M31_4) * (conv_tmp_93be2_45[37]))),
                    (((((M31_2) * (conv_tmp_93be2_45[10])) + (conv_tmp_93be2_45[16]))
                        + ((M31_32) * (conv_tmp_93be2_45[17])))
                        - ((M31_4) * (conv_tmp_93be2_45[38]))),
                    (((((M31_2) * (conv_tmp_93be2_45[11])) + (conv_tmp_93be2_45[17]))
                        + ((M31_32) * (conv_tmp_93be2_45[18])))
                        - ((M31_4) * (conv_tmp_93be2_45[39]))),
                    (((((M31_2) * (conv_tmp_93be2_45[12])) + (conv_tmp_93be2_45[18]))
                        + ((M31_32) * (conv_tmp_93be2_45[19])))
                        - ((M31_4) * (conv_tmp_93be2_45[40]))),
                    (((((M31_2) * (conv_tmp_93be2_45[13])) + (conv_tmp_93be2_45[19]))
                        + ((M31_32) * (conv_tmp_93be2_45[20])))
                        - ((M31_4) * (conv_tmp_93be2_45[41]))),
                    (((((M31_2) * (conv_tmp_93be2_45[14])) + (conv_tmp_93be2_45[20]))
                        - ((M31_4) * (conv_tmp_93be2_45[42])))
                        + ((M31_64) * (conv_tmp_93be2_45[49]))),
                    (((((M31_2) * (conv_tmp_93be2_45[15])) - ((M31_4) * (conv_tmp_93be2_45[43])))
                        + ((M31_2) * (conv_tmp_93be2_45[49])))
                        + ((M31_64) * (conv_tmp_93be2_45[50]))),
                    (((((M31_2) * (conv_tmp_93be2_45[16])) - ((M31_4) * (conv_tmp_93be2_45[44])))
                        + ((M31_2) * (conv_tmp_93be2_45[50])))
                        + ((M31_64) * (conv_tmp_93be2_45[51]))),
                    (((((M31_2) * (conv_tmp_93be2_45[17])) - ((M31_4) * (conv_tmp_93be2_45[45])))
                        + ((M31_2) * (conv_tmp_93be2_45[51])))
                        + ((M31_64) * (conv_tmp_93be2_45[52]))),
                    (((((M31_2) * (conv_tmp_93be2_45[18])) - ((M31_4) * (conv_tmp_93be2_45[46])))
                        + ((M31_2) * (conv_tmp_93be2_45[52])))
                        + ((M31_64) * (conv_tmp_93be2_45[53]))),
                    (((((M31_2) * (conv_tmp_93be2_45[19])) - ((M31_4) * (conv_tmp_93be2_45[47])))
                        + ((M31_2) * (conv_tmp_93be2_45[53])))
                        + ((M31_64) * (conv_tmp_93be2_45[54]))),
                    ((((M31_2) * (conv_tmp_93be2_45[20])) - ((M31_4) * (conv_tmp_93be2_45[48])))
                        + ((M31_2) * (conv_tmp_93be2_45[54]))),
                ];
                let k_mod_2_18_biased_tmp_93be2_47 =
                    ((((PackedUInt32::from_m31(((conv_mod_tmp_93be2_46[0]) + (M31_134217728))))
                        + (((PackedUInt32::from_m31(
                            ((conv_mod_tmp_93be2_46[1]) + (M31_134217728)),
                        )) & (UInt32_511))
                            << (UInt32_9)))
                        + (UInt32_131072))
                        & (UInt32_262143));
                let k_col101 = ((k_mod_2_18_biased_tmp_93be2_47.low().as_m31())
                    + (((k_mod_2_18_biased_tmp_93be2_47.high().as_m31()) - (M31_2)) * (M31_65536)));
                *row[101] = k_col101;
                *sub_component_inputs.range_check_20[0] = [((k_col101) + (M31_524288))];
                *lookup_data.range_check_20_7 = [M31_1410849886, ((k_col101) + (M31_524288))];
                let carry_0_col102 = (((conv_mod_tmp_93be2_46[0]) - (k_col101)) * (M31_4194304));
                *row[102] = carry_0_col102;
                *sub_component_inputs.range_check_20_b[0] = [((carry_0_col102) + (M31_524288))];
                *lookup_data.range_check_20_b_8 =
                    [M31_514232941, ((carry_0_col102) + (M31_524288))];
                let carry_1_col103 =
                    (((conv_mod_tmp_93be2_46[1]) + (carry_0_col102)) * (M31_4194304));
                *row[103] = carry_1_col103;
                *sub_component_inputs.range_check_20_c[0] = [((carry_1_col103) + (M31_524288))];
                *lookup_data.range_check_20_c_9 =
                    [M31_531010560, ((carry_1_col103) + (M31_524288))];
                let carry_2_col104 =
                    (((conv_mod_tmp_93be2_46[2]) + (carry_1_col103)) * (M31_4194304));
                *row[104] = carry_2_col104;
                *sub_component_inputs.range_check_20_d[0] = [((carry_2_col104) + (M31_524288))];
                *lookup_data.range_check_20_d_10 =
                    [M31_480677703, ((carry_2_col104) + (M31_524288))];
                let carry_3_col105 =
                    (((conv_mod_tmp_93be2_46[3]) + (carry_2_col104)) * (M31_4194304));
                *row[105] = carry_3_col105;
                *sub_component_inputs.range_check_20_e[0] = [((carry_3_col105) + (M31_524288))];
                *lookup_data.range_check_20_e_11 =
                    [M31_497455322, ((carry_3_col105) + (M31_524288))];
                let carry_4_col106 =
                    (((conv_mod_tmp_93be2_46[4]) + (carry_3_col105)) * (M31_4194304));
                *row[106] = carry_4_col106;
                *sub_component_inputs.range_check_20_f[0] = [((carry_4_col106) + (M31_524288))];
                *lookup_data.range_check_20_f_12 =
                    [M31_447122465, ((carry_4_col106) + (M31_524288))];
                let carry_5_col107 =
                    (((conv_mod_tmp_93be2_46[5]) + (carry_4_col106)) * (M31_4194304));
                *row[107] = carry_5_col107;
                *sub_component_inputs.range_check_20_g[0] = [((carry_5_col107) + (M31_524288))];
                *lookup_data.range_check_20_g_13 =
                    [M31_463900084, ((carry_5_col107) + (M31_524288))];
                let carry_6_col108 =
                    (((conv_mod_tmp_93be2_46[6]) + (carry_5_col107)) * (M31_4194304));
                *row[108] = carry_6_col108;
                *sub_component_inputs.range_check_20_h[0] = [((carry_6_col108) + (M31_524288))];
                *lookup_data.range_check_20_h_14 =
                    [M31_682009131, ((carry_6_col108) + (M31_524288))];
                let carry_7_col109 =
                    (((conv_mod_tmp_93be2_46[7]) + (carry_6_col108)) * (M31_4194304));
                *row[109] = carry_7_col109;
                *sub_component_inputs.range_check_20[1] = [((carry_7_col109) + (M31_524288))];
                *lookup_data.range_check_20_15 =
                    [M31_1410849886, ((carry_7_col109) + (M31_524288))];
                let carry_8_col110 =
                    (((conv_mod_tmp_93be2_46[8]) + (carry_7_col109)) * (M31_4194304));
                *row[110] = carry_8_col110;
                *sub_component_inputs.range_check_20_b[1] = [((carry_8_col110) + (M31_524288))];
                *lookup_data.range_check_20_b_16 =
                    [M31_514232941, ((carry_8_col110) + (M31_524288))];
                let carry_9_col111 =
                    (((conv_mod_tmp_93be2_46[9]) + (carry_8_col110)) * (M31_4194304));
                *row[111] = carry_9_col111;
                *sub_component_inputs.range_check_20_c[1] = [((carry_9_col111) + (M31_524288))];
                *lookup_data.range_check_20_c_17 =
                    [M31_531010560, ((carry_9_col111) + (M31_524288))];
                let carry_10_col112 =
                    (((conv_mod_tmp_93be2_46[10]) + (carry_9_col111)) * (M31_4194304));
                *row[112] = carry_10_col112;
                *sub_component_inputs.range_check_20_d[1] = [((carry_10_col112) + (M31_524288))];
                *lookup_data.range_check_20_d_18 =
                    [M31_480677703, ((carry_10_col112) + (M31_524288))];
                let carry_11_col113 =
                    (((conv_mod_tmp_93be2_46[11]) + (carry_10_col112)) * (M31_4194304));
                *row[113] = carry_11_col113;
                *sub_component_inputs.range_check_20_e[1] = [((carry_11_col113) + (M31_524288))];
                *lookup_data.range_check_20_e_19 =
                    [M31_497455322, ((carry_11_col113) + (M31_524288))];
                let carry_12_col114 =
                    (((conv_mod_tmp_93be2_46[12]) + (carry_11_col113)) * (M31_4194304));
                *row[114] = carry_12_col114;
                *sub_component_inputs.range_check_20_f[1] = [((carry_12_col114) + (M31_524288))];
                *lookup_data.range_check_20_f_20 =
                    [M31_447122465, ((carry_12_col114) + (M31_524288))];
                let carry_13_col115 =
                    (((conv_mod_tmp_93be2_46[13]) + (carry_12_col114)) * (M31_4194304));
                *row[115] = carry_13_col115;
                *sub_component_inputs.range_check_20_g[1] = [((carry_13_col115) + (M31_524288))];
                *lookup_data.range_check_20_g_21 =
                    [M31_463900084, ((carry_13_col115) + (M31_524288))];
                let carry_14_col116 =
                    (((conv_mod_tmp_93be2_46[14]) + (carry_13_col115)) * (M31_4194304));
                *row[116] = carry_14_col116;
                *sub_component_inputs.range_check_20_h[1] = [((carry_14_col116) + (M31_524288))];
                *lookup_data.range_check_20_h_22 =
                    [M31_682009131, ((carry_14_col116) + (M31_524288))];
                let carry_15_col117 =
                    (((conv_mod_tmp_93be2_46[15]) + (carry_14_col116)) * (M31_4194304));
                *row[117] = carry_15_col117;
                *sub_component_inputs.range_check_20[2] = [((carry_15_col117) + (M31_524288))];
                *lookup_data.range_check_20_23 =
                    [M31_1410849886, ((carry_15_col117) + (M31_524288))];
                let carry_16_col118 =
                    (((conv_mod_tmp_93be2_46[16]) + (carry_15_col117)) * (M31_4194304));
                *row[118] = carry_16_col118;
                *sub_component_inputs.range_check_20_b[2] = [((carry_16_col118) + (M31_524288))];
                *lookup_data.range_check_20_b_24 =
                    [M31_514232941, ((carry_16_col118) + (M31_524288))];
                let carry_17_col119 =
                    (((conv_mod_tmp_93be2_46[17]) + (carry_16_col118)) * (M31_4194304));
                *row[119] = carry_17_col119;
                *sub_component_inputs.range_check_20_c[2] = [((carry_17_col119) + (M31_524288))];
                *lookup_data.range_check_20_c_25 =
                    [M31_531010560, ((carry_17_col119) + (M31_524288))];
                let carry_18_col120 =
                    (((conv_mod_tmp_93be2_46[18]) + (carry_17_col119)) * (M31_4194304));
                *row[120] = carry_18_col120;
                *sub_component_inputs.range_check_20_d[2] = [((carry_18_col120) + (M31_524288))];
                *lookup_data.range_check_20_d_26 =
                    [M31_480677703, ((carry_18_col120) + (M31_524288))];
                let carry_19_col121 =
                    (((conv_mod_tmp_93be2_46[19]) + (carry_18_col120)) * (M31_4194304));
                *row[121] = carry_19_col121;
                *sub_component_inputs.range_check_20_e[2] = [((carry_19_col121) + (M31_524288))];
                *lookup_data.range_check_20_e_27 =
                    [M31_497455322, ((carry_19_col121) + (M31_524288))];
                let carry_20_col122 =
                    (((conv_mod_tmp_93be2_46[20]) + (carry_19_col121)) * (M31_4194304));
                *row[122] = carry_20_col122;
                *sub_component_inputs.range_check_20_f[2] = [((carry_20_col122) + (M31_524288))];
                *lookup_data.range_check_20_f_28 =
                    [M31_447122465, ((carry_20_col122) + (M31_524288))];
                let carry_21_col123 = ((((conv_mod_tmp_93be2_46[21]) - ((M31_136) * (k_col101)))
                    + (carry_20_col122))
                    * (M31_4194304));
                *row[123] = carry_21_col123;
                *sub_component_inputs.range_check_20_g[2] = [((carry_21_col123) + (M31_524288))];
                *lookup_data.range_check_20_g_29 =
                    [M31_463900084, ((carry_21_col123) + (M31_524288))];
                let carry_22_col124 =
                    (((conv_mod_tmp_93be2_46[22]) + (carry_21_col123)) * (M31_4194304));
                *row[124] = carry_22_col124;
                *sub_component_inputs.range_check_20_h[2] = [((carry_22_col124) + (M31_524288))];
                *lookup_data.range_check_20_h_30 =
                    [M31_682009131, ((carry_22_col124) + (M31_524288))];
                let carry_23_col125 =
                    (((conv_mod_tmp_93be2_46[23]) + (carry_22_col124)) * (M31_4194304));
                *row[125] = carry_23_col125;
                *sub_component_inputs.range_check_20[3] = [((carry_23_col125) + (M31_524288))];
                *lookup_data.range_check_20_31 =
                    [M31_1410849886, ((carry_23_col125) + (M31_524288))];
                let carry_24_col126 =
                    (((conv_mod_tmp_93be2_46[24]) + (carry_23_col125)) * (M31_4194304));
                *row[126] = carry_24_col126;
                *sub_component_inputs.range_check_20_b[3] = [((carry_24_col126) + (M31_524288))];
                *lookup_data.range_check_20_b_32 =
                    [M31_514232941, ((carry_24_col126) + (M31_524288))];
                let carry_25_col127 =
                    (((conv_mod_tmp_93be2_46[25]) + (carry_24_col126)) * (M31_4194304));
                *row[127] = carry_25_col127;
                *sub_component_inputs.range_check_20_c[3] = [((carry_25_col127) + (M31_524288))];
                *lookup_data.range_check_20_c_33 =
                    [M31_531010560, ((carry_25_col127) + (M31_524288))];
                let carry_26_col128 =
                    (((conv_mod_tmp_93be2_46[26]) + (carry_25_col127)) * (M31_4194304));
                *row[128] = carry_26_col128;
                *sub_component_inputs.range_check_20_d[3] = [((carry_26_col128) + (M31_524288))];
                *lookup_data.range_check_20_d_34 =
                    [M31_480677703, ((carry_26_col128) + (M31_524288))];

                let enabler_col129 = enabler_col.packed_at(row_index);
                *row[129] = enabler_col129;
                *lookup_data.opcodes_35 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_36 = [
                    M31_428564188,
                    (((input_pc_col0) + (M31_1)) + (op1_imm_col8)),
                    ((input_ap_col1) + (ap_update_add_1_col10)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col129;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `mul_opcode` — mechanical rewrite of
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
//     memory_address_to_id_5[3] 74..76
//     memory_id_to_big_6[30] 77..106
//     range_check_20_7[2] 107..108
//     range_check_20_b_8[2] 109..110
//     range_check_20_c_9[2] 111..112
//     range_check_20_d_10[2] 113..114
//     range_check_20_e_11[2] 115..116
//     range_check_20_f_12[2] 117..118
//     range_check_20_g_13[2] 119..120
//     range_check_20_h_14[2] 121..122
//     range_check_20_15[2] 123..124
//     range_check_20_b_16[2] 125..126
//     range_check_20_c_17[2] 127..128
//     range_check_20_d_18[2] 129..130
//     range_check_20_e_19[2] 131..132
//     range_check_20_f_20[2] 133..134
//     range_check_20_g_21[2] 135..136
//     range_check_20_h_22[2] 137..138
//     range_check_20_23[2] 139..140
//     range_check_20_b_24[2] 141..142
//     range_check_20_c_25[2] 143..144
//     range_check_20_d_26[2] 145..146
//     range_check_20_e_27[2] 147..148
//     range_check_20_f_28[2] 149..150
//     range_check_20_g_29[2] 151..152
//     range_check_20_h_30[2] 153..154
//     range_check_20_31[2] 155..156
//     range_check_20_b_32[2] 157..158
//     range_check_20_c_33[2] 159..160
//     range_check_20_d_34[2] 161..162
//     opcodes_35[4] 163..166
//     opcodes_36[4] 167..170
//     mults_0 171
//     mults_1 172
//     (173 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     memory_address_to_id[2] 9
//     memory_id_to_big[0] 10
//     memory_id_to_big[1] 11
//     memory_id_to_big[2] 12
//     range_check_20[0] 13
//     range_check_20[1] 14
//     range_check_20[2] 15
//     range_check_20[3] 16
//     range_check_20_b[0] 17
//     range_check_20_b[1] 18
//     range_check_20_b[2] 19
//     range_check_20_b[3] 20
//     range_check_20_c[0] 21
//     range_check_20_c[1] 22
//     range_check_20_c[2] 23
//     range_check_20_c[3] 24
//     range_check_20_d[0] 25
//     range_check_20_d[1] 26
//     range_check_20_d[2] 27
//     range_check_20_d[3] 28
//     range_check_20_e[0] 29
//     range_check_20_e[1] 30
//     range_check_20_e[2] 31
//     range_check_20_f[0] 32
//     range_check_20_f[1] 33
//     range_check_20_f[2] 34
//     range_check_20_g[0] 35
//     range_check_20_g[1] 36
//     range_check_20_g[2] 37
//     range_check_20_h[0] 38
//     range_check_20_h[1] 39
//     range_check_20_h[2] 40
//     (41 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 173;
pub(crate) const N_SUB_INPUT_WORDS: usize = 41;

/// The per-row `mul_opcode` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn mul_opcode_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_4 = eval.m31_const(4);
    let m31_8 = eval.m31_const(8);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_128 = eval.m31_const(128);
    let m31_136 = eval.m31_const(136);
    let m31_256 = eval.m31_const(256);
    let m31_32768 = eval.m31_const(32768);
    let m31_65536 = eval.m31_const(65536);
    let m31_524288 = eval.m31_const(524288);
    let m31_4194304 = eval.m31_const(4194304);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_447122465 = eval.m31_const(447122465);
    let m31_463900084 = eval.m31_const(463900084);
    let m31_480677703 = eval.m31_const(480677703);
    let m31_497455322 = eval.m31_const(497455322);
    let m31_514232941 = eval.m31_const(514232941);
    let m31_531010560 = eval.m31_const(531010560);
    let m31_682009131 = eval.m31_const(682009131);
    let m31_1410849886 = eval.m31_const(1410849886);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_93be2_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_93be2_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_93be2_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_93be2_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_93be2_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 1);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 7);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 2);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 2);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 3);
    let wg_v14 = eval.u16_from_m31(wg_v13);
    let wg_v15 = eval.u16_and(wg_v14, 31);
    let wg_v16 = eval.u16_shl(wg_v15, 11);
    let offset1_tmp_93be2_3 = eval.u16_add(wg_v12, wg_v16);
    let offset1_col4 = eval.u16_as_m31(offset1_tmp_93be2_3);
    eval.set_col(4, offset1_col4);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 3);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shr(wg_v18, 5);
    let wg_v20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 4);
    let wg_v21 = eval.u16_from_m31(wg_v20);
    let wg_v22 = eval.u16_shl(wg_v21, 4);
    let wg_v23 = eval.u16_add(wg_v19, wg_v22);
    let wg_v24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v25 = eval.u16_from_m31(wg_v24);
    let wg_v26 = eval.u16_and(wg_v25, 7);
    let wg_v27 = eval.u16_shl(wg_v26, 13);
    let offset2_tmp_93be2_4 = eval.u16_add(wg_v23, wg_v27);
    let offset2_col5 = eval.u16_as_m31(offset2_tmp_93be2_4);
    eval.set_col(5, offset2_col5);
    let wg_v28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v29 = eval.u16_from_m31(wg_v28);
    let wg_v30 = eval.u16_shr(wg_v29, 3);
    let wg_v31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 6);
    let wg_v32 = eval.u16_from_m31(wg_v31);
    let wg_v33 = eval.u16_shl(wg_v32, 6);
    let wg_v34 = eval.u16_add(wg_v30, wg_v33);
    let wg_v35 = eval.u16_shr(wg_v34, 0);
    let dst_base_fp_tmp_93be2_5 = eval.u16_and(wg_v35, 1);
    let dst_base_fp_col6 = eval.u16_as_m31(dst_base_fp_tmp_93be2_5);
    eval.set_col(6, dst_base_fp_col6);
    let wg_v36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v37 = eval.u16_from_m31(wg_v36);
    let wg_v38 = eval.u16_shr(wg_v37, 3);
    let wg_v39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 6);
    let wg_v40 = eval.u16_from_m31(wg_v39);
    let wg_v41 = eval.u16_shl(wg_v40, 6);
    let wg_v42 = eval.u16_add(wg_v38, wg_v41);
    let wg_v43 = eval.u16_shr(wg_v42, 1);
    let op0_base_fp_tmp_93be2_6 = eval.u16_and(wg_v43, 1);
    let op0_base_fp_col7 = eval.u16_as_m31(op0_base_fp_tmp_93be2_6);
    eval.set_col(7, op0_base_fp_col7);
    let wg_v44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v45 = eval.u16_from_m31(wg_v44);
    let wg_v46 = eval.u16_shr(wg_v45, 3);
    let wg_v47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 6);
    let wg_v48 = eval.u16_from_m31(wg_v47);
    let wg_v49 = eval.u16_shl(wg_v48, 6);
    let wg_v50 = eval.u16_add(wg_v46, wg_v49);
    let wg_v51 = eval.u16_shr(wg_v50, 2);
    let op1_imm_tmp_93be2_7 = eval.u16_and(wg_v51, 1);
    let op1_imm_col8 = eval.u16_as_m31(op1_imm_tmp_93be2_7);
    eval.set_col(8, op1_imm_col8);
    let wg_v52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v53 = eval.u16_from_m31(wg_v52);
    let wg_v54 = eval.u16_shr(wg_v53, 3);
    let wg_v55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 6);
    let wg_v56 = eval.u16_from_m31(wg_v55);
    let wg_v57 = eval.u16_shl(wg_v56, 6);
    let wg_v58 = eval.u16_add(wg_v54, wg_v57);
    let wg_v59 = eval.u16_shr(wg_v58, 3);
    let op1_base_fp_tmp_93be2_8 = eval.u16_and(wg_v59, 1);
    let op1_base_fp_col9 = eval.u16_as_m31(op1_base_fp_tmp_93be2_8);
    eval.set_col(9, op1_base_fp_col9);
    let wg_v60 = eval.m31_sub(m31_1, op1_imm_col8);
    let op1_base_ap_tmp_93be2_9 = eval.m31_sub(wg_v60, op1_base_fp_col9);
    let wg_v61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 5);
    let wg_v62 = eval.u16_from_m31(wg_v61);
    let wg_v63 = eval.u16_shr(wg_v62, 3);
    let wg_v64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_1.clone(), 6);
    let wg_v65 = eval.u16_from_m31(wg_v64);
    let wg_v66 = eval.u16_shl(wg_v65, 6);
    let wg_v67 = eval.u16_add(wg_v63, wg_v66);
    let wg_v68 = eval.u16_shr(wg_v67, 11);
    let ap_update_add_1_tmp_93be2_10 = eval.u16_and(wg_v68, 1);
    let ap_update_add_1_col10 = eval.u16_as_m31(ap_update_add_1_tmp_93be2_10);
    eval.set_col(10, ap_update_add_1_col10);
    let wg_v69 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v70 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v71 = eval.m31_add(wg_v69, wg_v70);
    let wg_v72 = eval.m31_mul(op1_imm_col8, m31_32);
    let wg_v73 = eval.m31_add(wg_v71, wg_v72);
    let wg_v74 = eval.m31_mul(op1_base_fp_col9, m31_64);
    let wg_v75 = eval.m31_add(wg_v73, wg_v74);
    let wg_v76 = eval.m31_mul(op1_base_ap_tmp_93be2_9, m31_128);
    let wg_v77 = eval.m31_add(wg_v75, wg_v76);
    let wg_v78 = eval.m31_mul(ap_update_add_1_col10, m31_32);
    let wg_v79 = eval.m31_add(m31_1, wg_v78);
    let wg_v80 = eval.m31_add(wg_v79, m31_256);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, offset0_col3);
    eval.set_sub_input_word(2, offset1_col4);
    eval.set_sub_input_word(3, offset2_col5);
    eval.set_sub_input_word(4, wg_v77);
    eval.set_sub_input_word(5, wg_v80);
    eval.set_sub_input_word(6, m31_0);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, offset0_col3);
    eval.set_lookup_word(3, offset1_col4);
    eval.set_lookup_word(4, offset2_col5);
    let wg_v81 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v82 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v83 = eval.m31_add(wg_v81, wg_v82);
    let wg_v84 = eval.m31_mul(op1_imm_col8, m31_32);
    let wg_v85 = eval.m31_add(wg_v83, wg_v84);
    let wg_v86 = eval.m31_mul(op1_base_fp_col9, m31_64);
    let wg_v87 = eval.m31_add(wg_v85, wg_v86);
    let wg_v88 = eval.m31_mul(op1_base_ap_tmp_93be2_9, m31_128);
    let wg_v89 = eval.m31_add(wg_v87, wg_v88);
    eval.set_lookup_word(5, wg_v89);
    let wg_v90 = eval.m31_mul(ap_update_add_1_col10, m31_32);
    let wg_v91 = eval.m31_add(m31_1, wg_v90);
    let wg_v92 = eval.m31_add(wg_v91, m31_256);
    eval.set_lookup_word(6, wg_v92);
    eval.set_lookup_word(7, m31_0);
    let wg_v93 = eval.m31_sub(offset0_col3, m31_32768);
    let wg_v94 = eval.m31_sub(offset1_col4, m31_32768);
    let wg_v95 = eval.m31_sub(offset2_col5, m31_32768);
    let decode_instruction_c630b_output_tmp_93be2_11 = (
        [wg_v93, wg_v94, wg_v95],
        [
            dst_base_fp_col6,
            op0_base_fp_col7,
            op1_imm_col8,
            op1_base_fp_col9,
            op1_base_ap_tmp_93be2_9,
            m31_0,
            m31_1,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            ap_update_add_1_col10,
            m31_0,
            m31_0,
            m31_1,
        ],
        m31_0,
    );
    let wg_v96 = eval.m31_mul(dst_base_fp_col6, input_fp_col2);
    let wg_v97 = eval.m31_sub(m31_1, dst_base_fp_col6);
    let wg_v98 = eval.m31_mul(wg_v97, input_ap_col1);
    let mem_dst_base_col11 = eval.m31_add(wg_v96, wg_v98);
    eval.set_col(11, mem_dst_base_col11);
    let wg_v99 = eval.m31_mul(op0_base_fp_col7, input_fp_col2);
    let wg_v100 = eval.m31_sub(m31_1, op0_base_fp_col7);
    let wg_v101 = eval.m31_mul(wg_v100, input_ap_col1);
    let mem0_base_col12 = eval.m31_add(wg_v99, wg_v101);
    eval.set_col(12, mem0_base_col12);
    let wg_v102 = eval.m31_mul(op1_imm_col8, input_pc_col0);
    let wg_v103 = eval.m31_mul(op1_base_fp_col9, input_fp_col2);
    let wg_v104 = eval.m31_add(wg_v102, wg_v103);
    let wg_v105 = eval.m31_mul(
        decode_instruction_c630b_output_tmp_93be2_11.1[4],
        input_ap_col1,
    );
    let mem1_base_col13 = eval.m31_add(wg_v104, wg_v105);
    eval.set_col(13, mem1_base_col13);
    let wg_v106 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_c630b_output_tmp_93be2_11.0[0],
    );
    let memory_address_to_id_value_tmp_93be2_12 = eval.mem_addr_to_id(wg_v106);
    let dst_id_col14 = memory_address_to_id_value_tmp_93be2_12;
    eval.set_col(14, dst_id_col14);
    let wg_v107 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_c630b_output_tmp_93be2_11.0[0],
    );
    eval.set_sub_input_word(7, wg_v107);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v108 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_c630b_output_tmp_93be2_11.0[0],
    );
    eval.set_lookup_word(9, wg_v108);
    eval.set_lookup_word(10, dst_id_col14);
    let memory_id_to_big_value_tmp_93be2_14 = eval.mem_id_to_value(dst_id_col14);
    let dst_limb_0_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 0);
    eval.set_col(15, dst_limb_0_col15);
    let dst_limb_1_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 1);
    eval.set_col(16, dst_limb_1_col16);
    let dst_limb_2_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 2);
    eval.set_col(17, dst_limb_2_col17);
    let dst_limb_3_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 3);
    eval.set_col(18, dst_limb_3_col18);
    let dst_limb_4_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 4);
    eval.set_col(19, dst_limb_4_col19);
    let dst_limb_5_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 5);
    eval.set_col(20, dst_limb_5_col20);
    let dst_limb_6_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 6);
    eval.set_col(21, dst_limb_6_col21);
    let dst_limb_7_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 7);
    eval.set_col(22, dst_limb_7_col22);
    let dst_limb_8_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 8);
    eval.set_col(23, dst_limb_8_col23);
    let dst_limb_9_col24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 9);
    eval.set_col(24, dst_limb_9_col24);
    let dst_limb_10_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 10);
    eval.set_col(25, dst_limb_10_col25);
    let dst_limb_11_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 11);
    eval.set_col(26, dst_limb_11_col26);
    let dst_limb_12_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 12);
    eval.set_col(27, dst_limb_12_col27);
    let dst_limb_13_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 13);
    eval.set_col(28, dst_limb_13_col28);
    let dst_limb_14_col29 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 14);
    eval.set_col(29, dst_limb_14_col29);
    let dst_limb_15_col30 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 15);
    eval.set_col(30, dst_limb_15_col30);
    let dst_limb_16_col31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 16);
    eval.set_col(31, dst_limb_16_col31);
    let dst_limb_17_col32 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 17);
    eval.set_col(32, dst_limb_17_col32);
    let dst_limb_18_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 18);
    eval.set_col(33, dst_limb_18_col33);
    let dst_limb_19_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 19);
    eval.set_col(34, dst_limb_19_col34);
    let dst_limb_20_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 20);
    eval.set_col(35, dst_limb_20_col35);
    let dst_limb_21_col36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 21);
    eval.set_col(36, dst_limb_21_col36);
    let dst_limb_22_col37 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 22);
    eval.set_col(37, dst_limb_22_col37);
    let dst_limb_23_col38 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 23);
    eval.set_col(38, dst_limb_23_col38);
    let dst_limb_24_col39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 24);
    eval.set_col(39, dst_limb_24_col39);
    let dst_limb_25_col40 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 25);
    eval.set_col(40, dst_limb_25_col40);
    let dst_limb_26_col41 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 26);
    eval.set_col(41, dst_limb_26_col41);
    let dst_limb_27_col42 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_14.clone(), 27);
    eval.set_col(42, dst_limb_27_col42);
    eval.set_sub_input_word(10, dst_id_col14);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, dst_id_col14);
    eval.set_lookup_word(13, dst_limb_0_col15);
    eval.set_lookup_word(14, dst_limb_1_col16);
    eval.set_lookup_word(15, dst_limb_2_col17);
    eval.set_lookup_word(16, dst_limb_3_col18);
    eval.set_lookup_word(17, dst_limb_4_col19);
    eval.set_lookup_word(18, dst_limb_5_col20);
    eval.set_lookup_word(19, dst_limb_6_col21);
    eval.set_lookup_word(20, dst_limb_7_col22);
    eval.set_lookup_word(21, dst_limb_8_col23);
    eval.set_lookup_word(22, dst_limb_9_col24);
    eval.set_lookup_word(23, dst_limb_10_col25);
    eval.set_lookup_word(24, dst_limb_11_col26);
    eval.set_lookup_word(25, dst_limb_12_col27);
    eval.set_lookup_word(26, dst_limb_13_col28);
    eval.set_lookup_word(27, dst_limb_14_col29);
    eval.set_lookup_word(28, dst_limb_15_col30);
    eval.set_lookup_word(29, dst_limb_16_col31);
    eval.set_lookup_word(30, dst_limb_17_col32);
    eval.set_lookup_word(31, dst_limb_18_col33);
    eval.set_lookup_word(32, dst_limb_19_col34);
    eval.set_lookup_word(33, dst_limb_20_col35);
    eval.set_lookup_word(34, dst_limb_21_col36);
    eval.set_lookup_word(35, dst_limb_22_col37);
    eval.set_lookup_word(36, dst_limb_23_col38);
    eval.set_lookup_word(37, dst_limb_24_col39);
    eval.set_lookup_word(38, dst_limb_25_col40);
    eval.set_lookup_word(39, dst_limb_26_col41);
    eval.set_lookup_word(40, dst_limb_27_col42);
    let read_positive_known_id_num_bits_252_output_tmp_93be2_15 = eval.felt_from_limbs([
        dst_limb_0_col15,
        dst_limb_1_col16,
        dst_limb_2_col17,
        dst_limb_3_col18,
        dst_limb_4_col19,
        dst_limb_5_col20,
        dst_limb_6_col21,
        dst_limb_7_col22,
        dst_limb_8_col23,
        dst_limb_9_col24,
        dst_limb_10_col25,
        dst_limb_11_col26,
        dst_limb_12_col27,
        dst_limb_13_col28,
        dst_limb_14_col29,
        dst_limb_15_col30,
        dst_limb_16_col31,
        dst_limb_17_col32,
        dst_limb_18_col33,
        dst_limb_19_col34,
        dst_limb_20_col35,
        dst_limb_21_col36,
        dst_limb_22_col37,
        dst_limb_23_col38,
        dst_limb_24_col39,
        dst_limb_25_col40,
        dst_limb_26_col41,
        dst_limb_27_col42,
    ]);
    let read_positive_num_bits_252_output_tmp_93be2_16 = (
        read_positive_known_id_num_bits_252_output_tmp_93be2_15.clone(),
        dst_id_col14,
    );
    let wg_v109 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_c630b_output_tmp_93be2_11.0[1],
    );
    let memory_address_to_id_value_tmp_93be2_17 = eval.mem_addr_to_id(wg_v109);
    let op0_id_col43 = memory_address_to_id_value_tmp_93be2_17;
    eval.set_col(43, op0_id_col43);
    let wg_v110 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_c630b_output_tmp_93be2_11.0[1],
    );
    eval.set_sub_input_word(8, wg_v110);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v111 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_c630b_output_tmp_93be2_11.0[1],
    );
    eval.set_lookup_word(42, wg_v111);
    eval.set_lookup_word(43, op0_id_col43);
    let memory_id_to_big_value_tmp_93be2_19 = eval.mem_id_to_value(op0_id_col43);
    let op0_limb_0_col44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 0);
    eval.set_col(44, op0_limb_0_col44);
    let op0_limb_1_col45 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 1);
    eval.set_col(45, op0_limb_1_col45);
    let op0_limb_2_col46 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 2);
    eval.set_col(46, op0_limb_2_col46);
    let op0_limb_3_col47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 3);
    eval.set_col(47, op0_limb_3_col47);
    let op0_limb_4_col48 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 4);
    eval.set_col(48, op0_limb_4_col48);
    let op0_limb_5_col49 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 5);
    eval.set_col(49, op0_limb_5_col49);
    let op0_limb_6_col50 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 6);
    eval.set_col(50, op0_limb_6_col50);
    let op0_limb_7_col51 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 7);
    eval.set_col(51, op0_limb_7_col51);
    let op0_limb_8_col52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 8);
    eval.set_col(52, op0_limb_8_col52);
    let op0_limb_9_col53 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 9);
    eval.set_col(53, op0_limb_9_col53);
    let op0_limb_10_col54 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 10);
    eval.set_col(54, op0_limb_10_col54);
    let op0_limb_11_col55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 11);
    eval.set_col(55, op0_limb_11_col55);
    let op0_limb_12_col56 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 12);
    eval.set_col(56, op0_limb_12_col56);
    let op0_limb_13_col57 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 13);
    eval.set_col(57, op0_limb_13_col57);
    let op0_limb_14_col58 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 14);
    eval.set_col(58, op0_limb_14_col58);
    let op0_limb_15_col59 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 15);
    eval.set_col(59, op0_limb_15_col59);
    let op0_limb_16_col60 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 16);
    eval.set_col(60, op0_limb_16_col60);
    let op0_limb_17_col61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 17);
    eval.set_col(61, op0_limb_17_col61);
    let op0_limb_18_col62 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 18);
    eval.set_col(62, op0_limb_18_col62);
    let op0_limb_19_col63 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 19);
    eval.set_col(63, op0_limb_19_col63);
    let op0_limb_20_col64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 20);
    eval.set_col(64, op0_limb_20_col64);
    let op0_limb_21_col65 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 21);
    eval.set_col(65, op0_limb_21_col65);
    let op0_limb_22_col66 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 22);
    eval.set_col(66, op0_limb_22_col66);
    let op0_limb_23_col67 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 23);
    eval.set_col(67, op0_limb_23_col67);
    let op0_limb_24_col68 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 24);
    eval.set_col(68, op0_limb_24_col68);
    let op0_limb_25_col69 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 25);
    eval.set_col(69, op0_limb_25_col69);
    let op0_limb_26_col70 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 26);
    eval.set_col(70, op0_limb_26_col70);
    let op0_limb_27_col71 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_19.clone(), 27);
    eval.set_col(71, op0_limb_27_col71);
    eval.set_sub_input_word(11, op0_id_col43);
    eval.set_lookup_word(44, m31_1662111297);
    eval.set_lookup_word(45, op0_id_col43);
    eval.set_lookup_word(46, op0_limb_0_col44);
    eval.set_lookup_word(47, op0_limb_1_col45);
    eval.set_lookup_word(48, op0_limb_2_col46);
    eval.set_lookup_word(49, op0_limb_3_col47);
    eval.set_lookup_word(50, op0_limb_4_col48);
    eval.set_lookup_word(51, op0_limb_5_col49);
    eval.set_lookup_word(52, op0_limb_6_col50);
    eval.set_lookup_word(53, op0_limb_7_col51);
    eval.set_lookup_word(54, op0_limb_8_col52);
    eval.set_lookup_word(55, op0_limb_9_col53);
    eval.set_lookup_word(56, op0_limb_10_col54);
    eval.set_lookup_word(57, op0_limb_11_col55);
    eval.set_lookup_word(58, op0_limb_12_col56);
    eval.set_lookup_word(59, op0_limb_13_col57);
    eval.set_lookup_word(60, op0_limb_14_col58);
    eval.set_lookup_word(61, op0_limb_15_col59);
    eval.set_lookup_word(62, op0_limb_16_col60);
    eval.set_lookup_word(63, op0_limb_17_col61);
    eval.set_lookup_word(64, op0_limb_18_col62);
    eval.set_lookup_word(65, op0_limb_19_col63);
    eval.set_lookup_word(66, op0_limb_20_col64);
    eval.set_lookup_word(67, op0_limb_21_col65);
    eval.set_lookup_word(68, op0_limb_22_col66);
    eval.set_lookup_word(69, op0_limb_23_col67);
    eval.set_lookup_word(70, op0_limb_24_col68);
    eval.set_lookup_word(71, op0_limb_25_col69);
    eval.set_lookup_word(72, op0_limb_26_col70);
    eval.set_lookup_word(73, op0_limb_27_col71);
    let read_positive_known_id_num_bits_252_output_tmp_93be2_20 = eval.felt_from_limbs([
        op0_limb_0_col44,
        op0_limb_1_col45,
        op0_limb_2_col46,
        op0_limb_3_col47,
        op0_limb_4_col48,
        op0_limb_5_col49,
        op0_limb_6_col50,
        op0_limb_7_col51,
        op0_limb_8_col52,
        op0_limb_9_col53,
        op0_limb_10_col54,
        op0_limb_11_col55,
        op0_limb_12_col56,
        op0_limb_13_col57,
        op0_limb_14_col58,
        op0_limb_15_col59,
        op0_limb_16_col60,
        op0_limb_17_col61,
        op0_limb_18_col62,
        op0_limb_19_col63,
        op0_limb_20_col64,
        op0_limb_21_col65,
        op0_limb_22_col66,
        op0_limb_23_col67,
        op0_limb_24_col68,
        op0_limb_25_col69,
        op0_limb_26_col70,
        op0_limb_27_col71,
    ]);
    let read_positive_num_bits_252_output_tmp_93be2_21 = (
        read_positive_known_id_num_bits_252_output_tmp_93be2_20.clone(),
        op0_id_col43,
    );
    let wg_v112 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_c630b_output_tmp_93be2_11.0[2],
    );
    let memory_address_to_id_value_tmp_93be2_22 = eval.mem_addr_to_id(wg_v112);
    let op1_id_col72 = memory_address_to_id_value_tmp_93be2_22;
    eval.set_col(72, op1_id_col72);
    let wg_v113 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_c630b_output_tmp_93be2_11.0[2],
    );
    eval.set_sub_input_word(9, wg_v113);
    eval.set_lookup_word(74, m31_1444891767);
    let wg_v114 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_c630b_output_tmp_93be2_11.0[2],
    );
    eval.set_lookup_word(75, wg_v114);
    eval.set_lookup_word(76, op1_id_col72);
    let memory_id_to_big_value_tmp_93be2_24 = eval.mem_id_to_value(op1_id_col72);
    let op1_limb_0_col73 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 0);
    eval.set_col(73, op1_limb_0_col73);
    let op1_limb_1_col74 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 1);
    eval.set_col(74, op1_limb_1_col74);
    let op1_limb_2_col75 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 2);
    eval.set_col(75, op1_limb_2_col75);
    let op1_limb_3_col76 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 3);
    eval.set_col(76, op1_limb_3_col76);
    let op1_limb_4_col77 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 4);
    eval.set_col(77, op1_limb_4_col77);
    let op1_limb_5_col78 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 5);
    eval.set_col(78, op1_limb_5_col78);
    let op1_limb_6_col79 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 6);
    eval.set_col(79, op1_limb_6_col79);
    let op1_limb_7_col80 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 7);
    eval.set_col(80, op1_limb_7_col80);
    let op1_limb_8_col81 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 8);
    eval.set_col(81, op1_limb_8_col81);
    let op1_limb_9_col82 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 9);
    eval.set_col(82, op1_limb_9_col82);
    let op1_limb_10_col83 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 10);
    eval.set_col(83, op1_limb_10_col83);
    let op1_limb_11_col84 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 11);
    eval.set_col(84, op1_limb_11_col84);
    let op1_limb_12_col85 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 12);
    eval.set_col(85, op1_limb_12_col85);
    let op1_limb_13_col86 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 13);
    eval.set_col(86, op1_limb_13_col86);
    let op1_limb_14_col87 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 14);
    eval.set_col(87, op1_limb_14_col87);
    let op1_limb_15_col88 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 15);
    eval.set_col(88, op1_limb_15_col88);
    let op1_limb_16_col89 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 16);
    eval.set_col(89, op1_limb_16_col89);
    let op1_limb_17_col90 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 17);
    eval.set_col(90, op1_limb_17_col90);
    let op1_limb_18_col91 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 18);
    eval.set_col(91, op1_limb_18_col91);
    let op1_limb_19_col92 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 19);
    eval.set_col(92, op1_limb_19_col92);
    let op1_limb_20_col93 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 20);
    eval.set_col(93, op1_limb_20_col93);
    let op1_limb_21_col94 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 21);
    eval.set_col(94, op1_limb_21_col94);
    let op1_limb_22_col95 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 22);
    eval.set_col(95, op1_limb_22_col95);
    let op1_limb_23_col96 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 23);
    eval.set_col(96, op1_limb_23_col96);
    let op1_limb_24_col97 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 24);
    eval.set_col(97, op1_limb_24_col97);
    let op1_limb_25_col98 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 25);
    eval.set_col(98, op1_limb_25_col98);
    let op1_limb_26_col99 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 26);
    eval.set_col(99, op1_limb_26_col99);
    let op1_limb_27_col100 = eval.felt_get_m31(&memory_id_to_big_value_tmp_93be2_24.clone(), 27);
    eval.set_col(100, op1_limb_27_col100);
    eval.set_sub_input_word(12, op1_id_col72);
    eval.set_lookup_word(77, m31_1662111297);
    eval.set_lookup_word(78, op1_id_col72);
    eval.set_lookup_word(79, op1_limb_0_col73);
    eval.set_lookup_word(80, op1_limb_1_col74);
    eval.set_lookup_word(81, op1_limb_2_col75);
    eval.set_lookup_word(82, op1_limb_3_col76);
    eval.set_lookup_word(83, op1_limb_4_col77);
    eval.set_lookup_word(84, op1_limb_5_col78);
    eval.set_lookup_word(85, op1_limb_6_col79);
    eval.set_lookup_word(86, op1_limb_7_col80);
    eval.set_lookup_word(87, op1_limb_8_col81);
    eval.set_lookup_word(88, op1_limb_9_col82);
    eval.set_lookup_word(89, op1_limb_10_col83);
    eval.set_lookup_word(90, op1_limb_11_col84);
    eval.set_lookup_word(91, op1_limb_12_col85);
    eval.set_lookup_word(92, op1_limb_13_col86);
    eval.set_lookup_word(93, op1_limb_14_col87);
    eval.set_lookup_word(94, op1_limb_15_col88);
    eval.set_lookup_word(95, op1_limb_16_col89);
    eval.set_lookup_word(96, op1_limb_17_col90);
    eval.set_lookup_word(97, op1_limb_18_col91);
    eval.set_lookup_word(98, op1_limb_19_col92);
    eval.set_lookup_word(99, op1_limb_20_col93);
    eval.set_lookup_word(100, op1_limb_21_col94);
    eval.set_lookup_word(101, op1_limb_22_col95);
    eval.set_lookup_word(102, op1_limb_23_col96);
    eval.set_lookup_word(103, op1_limb_24_col97);
    eval.set_lookup_word(104, op1_limb_25_col98);
    eval.set_lookup_word(105, op1_limb_26_col99);
    eval.set_lookup_word(106, op1_limb_27_col100);
    let read_positive_known_id_num_bits_252_output_tmp_93be2_25 = eval.felt_from_limbs([
        op1_limb_0_col73,
        op1_limb_1_col74,
        op1_limb_2_col75,
        op1_limb_3_col76,
        op1_limb_4_col77,
        op1_limb_5_col78,
        op1_limb_6_col79,
        op1_limb_7_col80,
        op1_limb_8_col81,
        op1_limb_9_col82,
        op1_limb_10_col83,
        op1_limb_11_col84,
        op1_limb_12_col85,
        op1_limb_13_col86,
        op1_limb_14_col87,
        op1_limb_15_col88,
        op1_limb_16_col89,
        op1_limb_17_col90,
        op1_limb_18_col91,
        op1_limb_19_col92,
        op1_limb_20_col93,
        op1_limb_21_col94,
        op1_limb_22_col95,
        op1_limb_23_col96,
        op1_limb_24_col97,
        op1_limb_25_col98,
        op1_limb_26_col99,
        op1_limb_27_col100,
    ]);
    let read_positive_num_bits_252_output_tmp_93be2_26 = (
        read_positive_known_id_num_bits_252_output_tmp_93be2_25.clone(),
        op1_id_col72,
    );
    let wg_v115 = eval.m31_mul(op0_limb_0_col44, op1_limb_0_col73);
    let wg_v116 = eval.m31_mul(op0_limb_0_col44, op1_limb_1_col74);
    let wg_v117 = eval.m31_mul(op0_limb_1_col45, op1_limb_0_col73);
    let wg_v118 = eval.m31_add(wg_v116, wg_v117);
    let wg_v119 = eval.m31_mul(op0_limb_0_col44, op1_limb_2_col75);
    let wg_v120 = eval.m31_mul(op0_limb_1_col45, op1_limb_1_col74);
    let wg_v121 = eval.m31_add(wg_v119, wg_v120);
    let wg_v122 = eval.m31_mul(op0_limb_2_col46, op1_limb_0_col73);
    let wg_v123 = eval.m31_add(wg_v121, wg_v122);
    let wg_v124 = eval.m31_mul(op0_limb_0_col44, op1_limb_3_col76);
    let wg_v125 = eval.m31_mul(op0_limb_1_col45, op1_limb_2_col75);
    let wg_v126 = eval.m31_add(wg_v124, wg_v125);
    let wg_v127 = eval.m31_mul(op0_limb_2_col46, op1_limb_1_col74);
    let wg_v128 = eval.m31_add(wg_v126, wg_v127);
    let wg_v129 = eval.m31_mul(op0_limb_3_col47, op1_limb_0_col73);
    let wg_v130 = eval.m31_add(wg_v128, wg_v129);
    let wg_v131 = eval.m31_mul(op0_limb_0_col44, op1_limb_4_col77);
    let wg_v132 = eval.m31_mul(op0_limb_1_col45, op1_limb_3_col76);
    let wg_v133 = eval.m31_add(wg_v131, wg_v132);
    let wg_v134 = eval.m31_mul(op0_limb_2_col46, op1_limb_2_col75);
    let wg_v135 = eval.m31_add(wg_v133, wg_v134);
    let wg_v136 = eval.m31_mul(op0_limb_3_col47, op1_limb_1_col74);
    let wg_v137 = eval.m31_add(wg_v135, wg_v136);
    let wg_v138 = eval.m31_mul(op0_limb_4_col48, op1_limb_0_col73);
    let wg_v139 = eval.m31_add(wg_v137, wg_v138);
    let wg_v140 = eval.m31_mul(op0_limb_0_col44, op1_limb_5_col78);
    let wg_v141 = eval.m31_mul(op0_limb_1_col45, op1_limb_4_col77);
    let wg_v142 = eval.m31_add(wg_v140, wg_v141);
    let wg_v143 = eval.m31_mul(op0_limb_2_col46, op1_limb_3_col76);
    let wg_v144 = eval.m31_add(wg_v142, wg_v143);
    let wg_v145 = eval.m31_mul(op0_limb_3_col47, op1_limb_2_col75);
    let wg_v146 = eval.m31_add(wg_v144, wg_v145);
    let wg_v147 = eval.m31_mul(op0_limb_4_col48, op1_limb_1_col74);
    let wg_v148 = eval.m31_add(wg_v146, wg_v147);
    let wg_v149 = eval.m31_mul(op0_limb_5_col49, op1_limb_0_col73);
    let wg_v150 = eval.m31_add(wg_v148, wg_v149);
    let wg_v151 = eval.m31_mul(op0_limb_0_col44, op1_limb_6_col79);
    let wg_v152 = eval.m31_mul(op0_limb_1_col45, op1_limb_5_col78);
    let wg_v153 = eval.m31_add(wg_v151, wg_v152);
    let wg_v154 = eval.m31_mul(op0_limb_2_col46, op1_limb_4_col77);
    let wg_v155 = eval.m31_add(wg_v153, wg_v154);
    let wg_v156 = eval.m31_mul(op0_limb_3_col47, op1_limb_3_col76);
    let wg_v157 = eval.m31_add(wg_v155, wg_v156);
    let wg_v158 = eval.m31_mul(op0_limb_4_col48, op1_limb_2_col75);
    let wg_v159 = eval.m31_add(wg_v157, wg_v158);
    let wg_v160 = eval.m31_mul(op0_limb_5_col49, op1_limb_1_col74);
    let wg_v161 = eval.m31_add(wg_v159, wg_v160);
    let wg_v162 = eval.m31_mul(op0_limb_6_col50, op1_limb_0_col73);
    let wg_v163 = eval.m31_add(wg_v161, wg_v162);
    let wg_v164 = eval.m31_mul(op0_limb_1_col45, op1_limb_6_col79);
    let wg_v165 = eval.m31_mul(op0_limb_2_col46, op1_limb_5_col78);
    let wg_v166 = eval.m31_add(wg_v164, wg_v165);
    let wg_v167 = eval.m31_mul(op0_limb_3_col47, op1_limb_4_col77);
    let wg_v168 = eval.m31_add(wg_v166, wg_v167);
    let wg_v169 = eval.m31_mul(op0_limb_4_col48, op1_limb_3_col76);
    let wg_v170 = eval.m31_add(wg_v168, wg_v169);
    let wg_v171 = eval.m31_mul(op0_limb_5_col49, op1_limb_2_col75);
    let wg_v172 = eval.m31_add(wg_v170, wg_v171);
    let wg_v173 = eval.m31_mul(op0_limb_6_col50, op1_limb_1_col74);
    let wg_v174 = eval.m31_add(wg_v172, wg_v173);
    let wg_v175 = eval.m31_mul(op0_limb_2_col46, op1_limb_6_col79);
    let wg_v176 = eval.m31_mul(op0_limb_3_col47, op1_limb_5_col78);
    let wg_v177 = eval.m31_add(wg_v175, wg_v176);
    let wg_v178 = eval.m31_mul(op0_limb_4_col48, op1_limb_4_col77);
    let wg_v179 = eval.m31_add(wg_v177, wg_v178);
    let wg_v180 = eval.m31_mul(op0_limb_5_col49, op1_limb_3_col76);
    let wg_v181 = eval.m31_add(wg_v179, wg_v180);
    let wg_v182 = eval.m31_mul(op0_limb_6_col50, op1_limb_2_col75);
    let wg_v183 = eval.m31_add(wg_v181, wg_v182);
    let wg_v184 = eval.m31_mul(op0_limb_3_col47, op1_limb_6_col79);
    let wg_v185 = eval.m31_mul(op0_limb_4_col48, op1_limb_5_col78);
    let wg_v186 = eval.m31_add(wg_v184, wg_v185);
    let wg_v187 = eval.m31_mul(op0_limb_5_col49, op1_limb_4_col77);
    let wg_v188 = eval.m31_add(wg_v186, wg_v187);
    let wg_v189 = eval.m31_mul(op0_limb_6_col50, op1_limb_3_col76);
    let wg_v190 = eval.m31_add(wg_v188, wg_v189);
    let wg_v191 = eval.m31_mul(op0_limb_4_col48, op1_limb_6_col79);
    let wg_v192 = eval.m31_mul(op0_limb_5_col49, op1_limb_5_col78);
    let wg_v193 = eval.m31_add(wg_v191, wg_v192);
    let wg_v194 = eval.m31_mul(op0_limb_6_col50, op1_limb_4_col77);
    let wg_v195 = eval.m31_add(wg_v193, wg_v194);
    let wg_v196 = eval.m31_mul(op0_limb_5_col49, op1_limb_6_col79);
    let wg_v197 = eval.m31_mul(op0_limb_6_col50, op1_limb_5_col78);
    let wg_v198 = eval.m31_add(wg_v196, wg_v197);
    let wg_v199 = eval.m31_mul(op0_limb_6_col50, op1_limb_6_col79);
    let z0_tmp_93be2_27 = [
        wg_v115, wg_v118, wg_v123, wg_v130, wg_v139, wg_v150, wg_v163, wg_v174, wg_v183, wg_v190,
        wg_v195, wg_v198, wg_v199,
    ];
    let wg_v200 = eval.m31_mul(op0_limb_7_col51, op1_limb_7_col80);
    let wg_v201 = eval.m31_mul(op0_limb_7_col51, op1_limb_8_col81);
    let wg_v202 = eval.m31_mul(op0_limb_8_col52, op1_limb_7_col80);
    let wg_v203 = eval.m31_add(wg_v201, wg_v202);
    let wg_v204 = eval.m31_mul(op0_limb_7_col51, op1_limb_9_col82);
    let wg_v205 = eval.m31_mul(op0_limb_8_col52, op1_limb_8_col81);
    let wg_v206 = eval.m31_add(wg_v204, wg_v205);
    let wg_v207 = eval.m31_mul(op0_limb_9_col53, op1_limb_7_col80);
    let wg_v208 = eval.m31_add(wg_v206, wg_v207);
    let wg_v209 = eval.m31_mul(op0_limb_7_col51, op1_limb_10_col83);
    let wg_v210 = eval.m31_mul(op0_limb_8_col52, op1_limb_9_col82);
    let wg_v211 = eval.m31_add(wg_v209, wg_v210);
    let wg_v212 = eval.m31_mul(op0_limb_9_col53, op1_limb_8_col81);
    let wg_v213 = eval.m31_add(wg_v211, wg_v212);
    let wg_v214 = eval.m31_mul(op0_limb_10_col54, op1_limb_7_col80);
    let wg_v215 = eval.m31_add(wg_v213, wg_v214);
    let wg_v216 = eval.m31_mul(op0_limb_7_col51, op1_limb_11_col84);
    let wg_v217 = eval.m31_mul(op0_limb_8_col52, op1_limb_10_col83);
    let wg_v218 = eval.m31_add(wg_v216, wg_v217);
    let wg_v219 = eval.m31_mul(op0_limb_9_col53, op1_limb_9_col82);
    let wg_v220 = eval.m31_add(wg_v218, wg_v219);
    let wg_v221 = eval.m31_mul(op0_limb_10_col54, op1_limb_8_col81);
    let wg_v222 = eval.m31_add(wg_v220, wg_v221);
    let wg_v223 = eval.m31_mul(op0_limb_11_col55, op1_limb_7_col80);
    let wg_v224 = eval.m31_add(wg_v222, wg_v223);
    let wg_v225 = eval.m31_mul(op0_limb_7_col51, op1_limb_12_col85);
    let wg_v226 = eval.m31_mul(op0_limb_8_col52, op1_limb_11_col84);
    let wg_v227 = eval.m31_add(wg_v225, wg_v226);
    let wg_v228 = eval.m31_mul(op0_limb_9_col53, op1_limb_10_col83);
    let wg_v229 = eval.m31_add(wg_v227, wg_v228);
    let wg_v230 = eval.m31_mul(op0_limb_10_col54, op1_limb_9_col82);
    let wg_v231 = eval.m31_add(wg_v229, wg_v230);
    let wg_v232 = eval.m31_mul(op0_limb_11_col55, op1_limb_8_col81);
    let wg_v233 = eval.m31_add(wg_v231, wg_v232);
    let wg_v234 = eval.m31_mul(op0_limb_12_col56, op1_limb_7_col80);
    let wg_v235 = eval.m31_add(wg_v233, wg_v234);
    let wg_v236 = eval.m31_mul(op0_limb_7_col51, op1_limb_13_col86);
    let wg_v237 = eval.m31_mul(op0_limb_8_col52, op1_limb_12_col85);
    let wg_v238 = eval.m31_add(wg_v236, wg_v237);
    let wg_v239 = eval.m31_mul(op0_limb_9_col53, op1_limb_11_col84);
    let wg_v240 = eval.m31_add(wg_v238, wg_v239);
    let wg_v241 = eval.m31_mul(op0_limb_10_col54, op1_limb_10_col83);
    let wg_v242 = eval.m31_add(wg_v240, wg_v241);
    let wg_v243 = eval.m31_mul(op0_limb_11_col55, op1_limb_9_col82);
    let wg_v244 = eval.m31_add(wg_v242, wg_v243);
    let wg_v245 = eval.m31_mul(op0_limb_12_col56, op1_limb_8_col81);
    let wg_v246 = eval.m31_add(wg_v244, wg_v245);
    let wg_v247 = eval.m31_mul(op0_limb_13_col57, op1_limb_7_col80);
    let wg_v248 = eval.m31_add(wg_v246, wg_v247);
    let wg_v249 = eval.m31_mul(op0_limb_8_col52, op1_limb_13_col86);
    let wg_v250 = eval.m31_mul(op0_limb_9_col53, op1_limb_12_col85);
    let wg_v251 = eval.m31_add(wg_v249, wg_v250);
    let wg_v252 = eval.m31_mul(op0_limb_10_col54, op1_limb_11_col84);
    let wg_v253 = eval.m31_add(wg_v251, wg_v252);
    let wg_v254 = eval.m31_mul(op0_limb_11_col55, op1_limb_10_col83);
    let wg_v255 = eval.m31_add(wg_v253, wg_v254);
    let wg_v256 = eval.m31_mul(op0_limb_12_col56, op1_limb_9_col82);
    let wg_v257 = eval.m31_add(wg_v255, wg_v256);
    let wg_v258 = eval.m31_mul(op0_limb_13_col57, op1_limb_8_col81);
    let wg_v259 = eval.m31_add(wg_v257, wg_v258);
    let wg_v260 = eval.m31_mul(op0_limb_9_col53, op1_limb_13_col86);
    let wg_v261 = eval.m31_mul(op0_limb_10_col54, op1_limb_12_col85);
    let wg_v262 = eval.m31_add(wg_v260, wg_v261);
    let wg_v263 = eval.m31_mul(op0_limb_11_col55, op1_limb_11_col84);
    let wg_v264 = eval.m31_add(wg_v262, wg_v263);
    let wg_v265 = eval.m31_mul(op0_limb_12_col56, op1_limb_10_col83);
    let wg_v266 = eval.m31_add(wg_v264, wg_v265);
    let wg_v267 = eval.m31_mul(op0_limb_13_col57, op1_limb_9_col82);
    let wg_v268 = eval.m31_add(wg_v266, wg_v267);
    let wg_v269 = eval.m31_mul(op0_limb_10_col54, op1_limb_13_col86);
    let wg_v270 = eval.m31_mul(op0_limb_11_col55, op1_limb_12_col85);
    let wg_v271 = eval.m31_add(wg_v269, wg_v270);
    let wg_v272 = eval.m31_mul(op0_limb_12_col56, op1_limb_11_col84);
    let wg_v273 = eval.m31_add(wg_v271, wg_v272);
    let wg_v274 = eval.m31_mul(op0_limb_13_col57, op1_limb_10_col83);
    let wg_v275 = eval.m31_add(wg_v273, wg_v274);
    let wg_v276 = eval.m31_mul(op0_limb_11_col55, op1_limb_13_col86);
    let wg_v277 = eval.m31_mul(op0_limb_12_col56, op1_limb_12_col85);
    let wg_v278 = eval.m31_add(wg_v276, wg_v277);
    let wg_v279 = eval.m31_mul(op0_limb_13_col57, op1_limb_11_col84);
    let wg_v280 = eval.m31_add(wg_v278, wg_v279);
    let wg_v281 = eval.m31_mul(op0_limb_12_col56, op1_limb_13_col86);
    let wg_v282 = eval.m31_mul(op0_limb_13_col57, op1_limb_12_col85);
    let wg_v283 = eval.m31_add(wg_v281, wg_v282);
    let wg_v284 = eval.m31_mul(op0_limb_13_col57, op1_limb_13_col86);
    let z2_tmp_93be2_28 = [
        wg_v200, wg_v203, wg_v208, wg_v215, wg_v224, wg_v235, wg_v248, wg_v259, wg_v268, wg_v275,
        wg_v280, wg_v283, wg_v284,
    ];
    let wg_v285 = eval.m31_add(op0_limb_0_col44, op0_limb_7_col51);
    let wg_v286 = eval.m31_add(op0_limb_1_col45, op0_limb_8_col52);
    let wg_v287 = eval.m31_add(op0_limb_2_col46, op0_limb_9_col53);
    let wg_v288 = eval.m31_add(op0_limb_3_col47, op0_limb_10_col54);
    let wg_v289 = eval.m31_add(op0_limb_4_col48, op0_limb_11_col55);
    let wg_v290 = eval.m31_add(op0_limb_5_col49, op0_limb_12_col56);
    let wg_v291 = eval.m31_add(op0_limb_6_col50, op0_limb_13_col57);
    let x_sum_tmp_93be2_29 = [
        wg_v285, wg_v286, wg_v287, wg_v288, wg_v289, wg_v290, wg_v291,
    ];
    let wg_v292 = eval.m31_add(op1_limb_0_col73, op1_limb_7_col80);
    let wg_v293 = eval.m31_add(op1_limb_1_col74, op1_limb_8_col81);
    let wg_v294 = eval.m31_add(op1_limb_2_col75, op1_limb_9_col82);
    let wg_v295 = eval.m31_add(op1_limb_3_col76, op1_limb_10_col83);
    let wg_v296 = eval.m31_add(op1_limb_4_col77, op1_limb_11_col84);
    let wg_v297 = eval.m31_add(op1_limb_5_col78, op1_limb_12_col85);
    let wg_v298 = eval.m31_add(op1_limb_6_col79, op1_limb_13_col86);
    let y_sum_tmp_93be2_30 = [
        wg_v292, wg_v293, wg_v294, wg_v295, wg_v296, wg_v297, wg_v298,
    ];
    let wg_v299 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[0]);
    let wg_v300 = eval.m31_sub(wg_v299, z0_tmp_93be2_27[0]);
    let wg_v301 = eval.m31_sub(wg_v300, z2_tmp_93be2_28[0]);
    let wg_v302 = eval.m31_add(z0_tmp_93be2_27[7], wg_v301);
    let wg_v303 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[1]);
    let wg_v304 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[0]);
    let wg_v305 = eval.m31_add(wg_v303, wg_v304);
    let wg_v306 = eval.m31_sub(wg_v305, z0_tmp_93be2_27[1]);
    let wg_v307 = eval.m31_sub(wg_v306, z2_tmp_93be2_28[1]);
    let wg_v308 = eval.m31_add(z0_tmp_93be2_27[8], wg_v307);
    let wg_v309 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[2]);
    let wg_v310 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[1]);
    let wg_v311 = eval.m31_add(wg_v309, wg_v310);
    let wg_v312 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[0]);
    let wg_v313 = eval.m31_add(wg_v311, wg_v312);
    let wg_v314 = eval.m31_sub(wg_v313, z0_tmp_93be2_27[2]);
    let wg_v315 = eval.m31_sub(wg_v314, z2_tmp_93be2_28[2]);
    let wg_v316 = eval.m31_add(z0_tmp_93be2_27[9], wg_v315);
    let wg_v317 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[3]);
    let wg_v318 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[2]);
    let wg_v319 = eval.m31_add(wg_v317, wg_v318);
    let wg_v320 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[1]);
    let wg_v321 = eval.m31_add(wg_v319, wg_v320);
    let wg_v322 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[0]);
    let wg_v323 = eval.m31_add(wg_v321, wg_v322);
    let wg_v324 = eval.m31_sub(wg_v323, z0_tmp_93be2_27[3]);
    let wg_v325 = eval.m31_sub(wg_v324, z2_tmp_93be2_28[3]);
    let wg_v326 = eval.m31_add(z0_tmp_93be2_27[10], wg_v325);
    let wg_v327 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[4]);
    let wg_v328 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[3]);
    let wg_v329 = eval.m31_add(wg_v327, wg_v328);
    let wg_v330 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[2]);
    let wg_v331 = eval.m31_add(wg_v329, wg_v330);
    let wg_v332 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[1]);
    let wg_v333 = eval.m31_add(wg_v331, wg_v332);
    let wg_v334 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[0]);
    let wg_v335 = eval.m31_add(wg_v333, wg_v334);
    let wg_v336 = eval.m31_sub(wg_v335, z0_tmp_93be2_27[4]);
    let wg_v337 = eval.m31_sub(wg_v336, z2_tmp_93be2_28[4]);
    let wg_v338 = eval.m31_add(z0_tmp_93be2_27[11], wg_v337);
    let wg_v339 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[5]);
    let wg_v340 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[4]);
    let wg_v341 = eval.m31_add(wg_v339, wg_v340);
    let wg_v342 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[3]);
    let wg_v343 = eval.m31_add(wg_v341, wg_v342);
    let wg_v344 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[2]);
    let wg_v345 = eval.m31_add(wg_v343, wg_v344);
    let wg_v346 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[1]);
    let wg_v347 = eval.m31_add(wg_v345, wg_v346);
    let wg_v348 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[0]);
    let wg_v349 = eval.m31_add(wg_v347, wg_v348);
    let wg_v350 = eval.m31_sub(wg_v349, z0_tmp_93be2_27[5]);
    let wg_v351 = eval.m31_sub(wg_v350, z2_tmp_93be2_28[5]);
    let wg_v352 = eval.m31_add(z0_tmp_93be2_27[12], wg_v351);
    let wg_v353 = eval.m31_mul(x_sum_tmp_93be2_29[0], y_sum_tmp_93be2_30[6]);
    let wg_v354 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[5]);
    let wg_v355 = eval.m31_add(wg_v353, wg_v354);
    let wg_v356 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[4]);
    let wg_v357 = eval.m31_add(wg_v355, wg_v356);
    let wg_v358 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[3]);
    let wg_v359 = eval.m31_add(wg_v357, wg_v358);
    let wg_v360 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[2]);
    let wg_v361 = eval.m31_add(wg_v359, wg_v360);
    let wg_v362 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[1]);
    let wg_v363 = eval.m31_add(wg_v361, wg_v362);
    let wg_v364 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[0]);
    let wg_v365 = eval.m31_add(wg_v363, wg_v364);
    let wg_v366 = eval.m31_sub(wg_v365, z0_tmp_93be2_27[6]);
    let wg_v367 = eval.m31_sub(wg_v366, z2_tmp_93be2_28[6]);
    let wg_v368 = eval.m31_mul(x_sum_tmp_93be2_29[1], y_sum_tmp_93be2_30[6]);
    let wg_v369 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[5]);
    let wg_v370 = eval.m31_add(wg_v368, wg_v369);
    let wg_v371 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[4]);
    let wg_v372 = eval.m31_add(wg_v370, wg_v371);
    let wg_v373 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[3]);
    let wg_v374 = eval.m31_add(wg_v372, wg_v373);
    let wg_v375 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[2]);
    let wg_v376 = eval.m31_add(wg_v374, wg_v375);
    let wg_v377 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[1]);
    let wg_v378 = eval.m31_add(wg_v376, wg_v377);
    let wg_v379 = eval.m31_sub(wg_v378, z0_tmp_93be2_27[7]);
    let wg_v380 = eval.m31_sub(wg_v379, z2_tmp_93be2_28[7]);
    let wg_v381 = eval.m31_add(z2_tmp_93be2_28[0], wg_v380);
    let wg_v382 = eval.m31_mul(x_sum_tmp_93be2_29[2], y_sum_tmp_93be2_30[6]);
    let wg_v383 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[5]);
    let wg_v384 = eval.m31_add(wg_v382, wg_v383);
    let wg_v385 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[4]);
    let wg_v386 = eval.m31_add(wg_v384, wg_v385);
    let wg_v387 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[3]);
    let wg_v388 = eval.m31_add(wg_v386, wg_v387);
    let wg_v389 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[2]);
    let wg_v390 = eval.m31_add(wg_v388, wg_v389);
    let wg_v391 = eval.m31_sub(wg_v390, z0_tmp_93be2_27[8]);
    let wg_v392 = eval.m31_sub(wg_v391, z2_tmp_93be2_28[8]);
    let wg_v393 = eval.m31_add(z2_tmp_93be2_28[1], wg_v392);
    let wg_v394 = eval.m31_mul(x_sum_tmp_93be2_29[3], y_sum_tmp_93be2_30[6]);
    let wg_v395 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[5]);
    let wg_v396 = eval.m31_add(wg_v394, wg_v395);
    let wg_v397 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[4]);
    let wg_v398 = eval.m31_add(wg_v396, wg_v397);
    let wg_v399 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[3]);
    let wg_v400 = eval.m31_add(wg_v398, wg_v399);
    let wg_v401 = eval.m31_sub(wg_v400, z0_tmp_93be2_27[9]);
    let wg_v402 = eval.m31_sub(wg_v401, z2_tmp_93be2_28[9]);
    let wg_v403 = eval.m31_add(z2_tmp_93be2_28[2], wg_v402);
    let wg_v404 = eval.m31_mul(x_sum_tmp_93be2_29[4], y_sum_tmp_93be2_30[6]);
    let wg_v405 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[5]);
    let wg_v406 = eval.m31_add(wg_v404, wg_v405);
    let wg_v407 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[4]);
    let wg_v408 = eval.m31_add(wg_v406, wg_v407);
    let wg_v409 = eval.m31_sub(wg_v408, z0_tmp_93be2_27[10]);
    let wg_v410 = eval.m31_sub(wg_v409, z2_tmp_93be2_28[10]);
    let wg_v411 = eval.m31_add(z2_tmp_93be2_28[3], wg_v410);
    let wg_v412 = eval.m31_mul(x_sum_tmp_93be2_29[5], y_sum_tmp_93be2_30[6]);
    let wg_v413 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[5]);
    let wg_v414 = eval.m31_add(wg_v412, wg_v413);
    let wg_v415 = eval.m31_sub(wg_v414, z0_tmp_93be2_27[11]);
    let wg_v416 = eval.m31_sub(wg_v415, z2_tmp_93be2_28[11]);
    let wg_v417 = eval.m31_add(z2_tmp_93be2_28[4], wg_v416);
    let wg_v418 = eval.m31_mul(x_sum_tmp_93be2_29[6], y_sum_tmp_93be2_30[6]);
    let wg_v419 = eval.m31_sub(wg_v418, z0_tmp_93be2_27[12]);
    let wg_v420 = eval.m31_sub(wg_v419, z2_tmp_93be2_28[12]);
    let wg_v421 = eval.m31_add(z2_tmp_93be2_28[5], wg_v420);
    let single_karatsuba_n_7_output_tmp_93be2_31 = [
        z0_tmp_93be2_27[0],
        z0_tmp_93be2_27[1],
        z0_tmp_93be2_27[2],
        z0_tmp_93be2_27[3],
        z0_tmp_93be2_27[4],
        z0_tmp_93be2_27[5],
        z0_tmp_93be2_27[6],
        wg_v302,
        wg_v308,
        wg_v316,
        wg_v326,
        wg_v338,
        wg_v352,
        wg_v367,
        wg_v381,
        wg_v393,
        wg_v403,
        wg_v411,
        wg_v417,
        wg_v421,
        z2_tmp_93be2_28[6],
        z2_tmp_93be2_28[7],
        z2_tmp_93be2_28[8],
        z2_tmp_93be2_28[9],
        z2_tmp_93be2_28[10],
        z2_tmp_93be2_28[11],
        z2_tmp_93be2_28[12],
    ];
    let wg_v422 = eval.m31_mul(op0_limb_14_col58, op1_limb_14_col87);
    let wg_v423 = eval.m31_mul(op0_limb_14_col58, op1_limb_15_col88);
    let wg_v424 = eval.m31_mul(op0_limb_15_col59, op1_limb_14_col87);
    let wg_v425 = eval.m31_add(wg_v423, wg_v424);
    let wg_v426 = eval.m31_mul(op0_limb_14_col58, op1_limb_16_col89);
    let wg_v427 = eval.m31_mul(op0_limb_15_col59, op1_limb_15_col88);
    let wg_v428 = eval.m31_add(wg_v426, wg_v427);
    let wg_v429 = eval.m31_mul(op0_limb_16_col60, op1_limb_14_col87);
    let wg_v430 = eval.m31_add(wg_v428, wg_v429);
    let wg_v431 = eval.m31_mul(op0_limb_14_col58, op1_limb_17_col90);
    let wg_v432 = eval.m31_mul(op0_limb_15_col59, op1_limb_16_col89);
    let wg_v433 = eval.m31_add(wg_v431, wg_v432);
    let wg_v434 = eval.m31_mul(op0_limb_16_col60, op1_limb_15_col88);
    let wg_v435 = eval.m31_add(wg_v433, wg_v434);
    let wg_v436 = eval.m31_mul(op0_limb_17_col61, op1_limb_14_col87);
    let wg_v437 = eval.m31_add(wg_v435, wg_v436);
    let wg_v438 = eval.m31_mul(op0_limb_14_col58, op1_limb_18_col91);
    let wg_v439 = eval.m31_mul(op0_limb_15_col59, op1_limb_17_col90);
    let wg_v440 = eval.m31_add(wg_v438, wg_v439);
    let wg_v441 = eval.m31_mul(op0_limb_16_col60, op1_limb_16_col89);
    let wg_v442 = eval.m31_add(wg_v440, wg_v441);
    let wg_v443 = eval.m31_mul(op0_limb_17_col61, op1_limb_15_col88);
    let wg_v444 = eval.m31_add(wg_v442, wg_v443);
    let wg_v445 = eval.m31_mul(op0_limb_18_col62, op1_limb_14_col87);
    let wg_v446 = eval.m31_add(wg_v444, wg_v445);
    let wg_v447 = eval.m31_mul(op0_limb_14_col58, op1_limb_19_col92);
    let wg_v448 = eval.m31_mul(op0_limb_15_col59, op1_limb_18_col91);
    let wg_v449 = eval.m31_add(wg_v447, wg_v448);
    let wg_v450 = eval.m31_mul(op0_limb_16_col60, op1_limb_17_col90);
    let wg_v451 = eval.m31_add(wg_v449, wg_v450);
    let wg_v452 = eval.m31_mul(op0_limb_17_col61, op1_limb_16_col89);
    let wg_v453 = eval.m31_add(wg_v451, wg_v452);
    let wg_v454 = eval.m31_mul(op0_limb_18_col62, op1_limb_15_col88);
    let wg_v455 = eval.m31_add(wg_v453, wg_v454);
    let wg_v456 = eval.m31_mul(op0_limb_19_col63, op1_limb_14_col87);
    let wg_v457 = eval.m31_add(wg_v455, wg_v456);
    let wg_v458 = eval.m31_mul(op0_limb_14_col58, op1_limb_20_col93);
    let wg_v459 = eval.m31_mul(op0_limb_15_col59, op1_limb_19_col92);
    let wg_v460 = eval.m31_add(wg_v458, wg_v459);
    let wg_v461 = eval.m31_mul(op0_limb_16_col60, op1_limb_18_col91);
    let wg_v462 = eval.m31_add(wg_v460, wg_v461);
    let wg_v463 = eval.m31_mul(op0_limb_17_col61, op1_limb_17_col90);
    let wg_v464 = eval.m31_add(wg_v462, wg_v463);
    let wg_v465 = eval.m31_mul(op0_limb_18_col62, op1_limb_16_col89);
    let wg_v466 = eval.m31_add(wg_v464, wg_v465);
    let wg_v467 = eval.m31_mul(op0_limb_19_col63, op1_limb_15_col88);
    let wg_v468 = eval.m31_add(wg_v466, wg_v467);
    let wg_v469 = eval.m31_mul(op0_limb_20_col64, op1_limb_14_col87);
    let wg_v470 = eval.m31_add(wg_v468, wg_v469);
    let wg_v471 = eval.m31_mul(op0_limb_15_col59, op1_limb_20_col93);
    let wg_v472 = eval.m31_mul(op0_limb_16_col60, op1_limb_19_col92);
    let wg_v473 = eval.m31_add(wg_v471, wg_v472);
    let wg_v474 = eval.m31_mul(op0_limb_17_col61, op1_limb_18_col91);
    let wg_v475 = eval.m31_add(wg_v473, wg_v474);
    let wg_v476 = eval.m31_mul(op0_limb_18_col62, op1_limb_17_col90);
    let wg_v477 = eval.m31_add(wg_v475, wg_v476);
    let wg_v478 = eval.m31_mul(op0_limb_19_col63, op1_limb_16_col89);
    let wg_v479 = eval.m31_add(wg_v477, wg_v478);
    let wg_v480 = eval.m31_mul(op0_limb_20_col64, op1_limb_15_col88);
    let wg_v481 = eval.m31_add(wg_v479, wg_v480);
    let wg_v482 = eval.m31_mul(op0_limb_16_col60, op1_limb_20_col93);
    let wg_v483 = eval.m31_mul(op0_limb_17_col61, op1_limb_19_col92);
    let wg_v484 = eval.m31_add(wg_v482, wg_v483);
    let wg_v485 = eval.m31_mul(op0_limb_18_col62, op1_limb_18_col91);
    let wg_v486 = eval.m31_add(wg_v484, wg_v485);
    let wg_v487 = eval.m31_mul(op0_limb_19_col63, op1_limb_17_col90);
    let wg_v488 = eval.m31_add(wg_v486, wg_v487);
    let wg_v489 = eval.m31_mul(op0_limb_20_col64, op1_limb_16_col89);
    let wg_v490 = eval.m31_add(wg_v488, wg_v489);
    let wg_v491 = eval.m31_mul(op0_limb_17_col61, op1_limb_20_col93);
    let wg_v492 = eval.m31_mul(op0_limb_18_col62, op1_limb_19_col92);
    let wg_v493 = eval.m31_add(wg_v491, wg_v492);
    let wg_v494 = eval.m31_mul(op0_limb_19_col63, op1_limb_18_col91);
    let wg_v495 = eval.m31_add(wg_v493, wg_v494);
    let wg_v496 = eval.m31_mul(op0_limb_20_col64, op1_limb_17_col90);
    let wg_v497 = eval.m31_add(wg_v495, wg_v496);
    let wg_v498 = eval.m31_mul(op0_limb_18_col62, op1_limb_20_col93);
    let wg_v499 = eval.m31_mul(op0_limb_19_col63, op1_limb_19_col92);
    let wg_v500 = eval.m31_add(wg_v498, wg_v499);
    let wg_v501 = eval.m31_mul(op0_limb_20_col64, op1_limb_18_col91);
    let wg_v502 = eval.m31_add(wg_v500, wg_v501);
    let wg_v503 = eval.m31_mul(op0_limb_19_col63, op1_limb_20_col93);
    let wg_v504 = eval.m31_mul(op0_limb_20_col64, op1_limb_19_col92);
    let wg_v505 = eval.m31_add(wg_v503, wg_v504);
    let wg_v506 = eval.m31_mul(op0_limb_20_col64, op1_limb_20_col93);
    let z0_tmp_93be2_32 = [
        wg_v422, wg_v425, wg_v430, wg_v437, wg_v446, wg_v457, wg_v470, wg_v481, wg_v490, wg_v497,
        wg_v502, wg_v505, wg_v506,
    ];
    let wg_v507 = eval.m31_mul(op0_limb_21_col65, op1_limb_21_col94);
    let wg_v508 = eval.m31_mul(op0_limb_21_col65, op1_limb_22_col95);
    let wg_v509 = eval.m31_mul(op0_limb_22_col66, op1_limb_21_col94);
    let wg_v510 = eval.m31_add(wg_v508, wg_v509);
    let wg_v511 = eval.m31_mul(op0_limb_21_col65, op1_limb_23_col96);
    let wg_v512 = eval.m31_mul(op0_limb_22_col66, op1_limb_22_col95);
    let wg_v513 = eval.m31_add(wg_v511, wg_v512);
    let wg_v514 = eval.m31_mul(op0_limb_23_col67, op1_limb_21_col94);
    let wg_v515 = eval.m31_add(wg_v513, wg_v514);
    let wg_v516 = eval.m31_mul(op0_limb_21_col65, op1_limb_24_col97);
    let wg_v517 = eval.m31_mul(op0_limb_22_col66, op1_limb_23_col96);
    let wg_v518 = eval.m31_add(wg_v516, wg_v517);
    let wg_v519 = eval.m31_mul(op0_limb_23_col67, op1_limb_22_col95);
    let wg_v520 = eval.m31_add(wg_v518, wg_v519);
    let wg_v521 = eval.m31_mul(op0_limb_24_col68, op1_limb_21_col94);
    let wg_v522 = eval.m31_add(wg_v520, wg_v521);
    let wg_v523 = eval.m31_mul(op0_limb_21_col65, op1_limb_25_col98);
    let wg_v524 = eval.m31_mul(op0_limb_22_col66, op1_limb_24_col97);
    let wg_v525 = eval.m31_add(wg_v523, wg_v524);
    let wg_v526 = eval.m31_mul(op0_limb_23_col67, op1_limb_23_col96);
    let wg_v527 = eval.m31_add(wg_v525, wg_v526);
    let wg_v528 = eval.m31_mul(op0_limb_24_col68, op1_limb_22_col95);
    let wg_v529 = eval.m31_add(wg_v527, wg_v528);
    let wg_v530 = eval.m31_mul(op0_limb_25_col69, op1_limb_21_col94);
    let wg_v531 = eval.m31_add(wg_v529, wg_v530);
    let wg_v532 = eval.m31_mul(op0_limb_21_col65, op1_limb_26_col99);
    let wg_v533 = eval.m31_mul(op0_limb_22_col66, op1_limb_25_col98);
    let wg_v534 = eval.m31_add(wg_v532, wg_v533);
    let wg_v535 = eval.m31_mul(op0_limb_23_col67, op1_limb_24_col97);
    let wg_v536 = eval.m31_add(wg_v534, wg_v535);
    let wg_v537 = eval.m31_mul(op0_limb_24_col68, op1_limb_23_col96);
    let wg_v538 = eval.m31_add(wg_v536, wg_v537);
    let wg_v539 = eval.m31_mul(op0_limb_25_col69, op1_limb_22_col95);
    let wg_v540 = eval.m31_add(wg_v538, wg_v539);
    let wg_v541 = eval.m31_mul(op0_limb_26_col70, op1_limb_21_col94);
    let wg_v542 = eval.m31_add(wg_v540, wg_v541);
    let wg_v543 = eval.m31_mul(op0_limb_21_col65, op1_limb_27_col100);
    let wg_v544 = eval.m31_mul(op0_limb_22_col66, op1_limb_26_col99);
    let wg_v545 = eval.m31_add(wg_v543, wg_v544);
    let wg_v546 = eval.m31_mul(op0_limb_23_col67, op1_limb_25_col98);
    let wg_v547 = eval.m31_add(wg_v545, wg_v546);
    let wg_v548 = eval.m31_mul(op0_limb_24_col68, op1_limb_24_col97);
    let wg_v549 = eval.m31_add(wg_v547, wg_v548);
    let wg_v550 = eval.m31_mul(op0_limb_25_col69, op1_limb_23_col96);
    let wg_v551 = eval.m31_add(wg_v549, wg_v550);
    let wg_v552 = eval.m31_mul(op0_limb_26_col70, op1_limb_22_col95);
    let wg_v553 = eval.m31_add(wg_v551, wg_v552);
    let wg_v554 = eval.m31_mul(op0_limb_27_col71, op1_limb_21_col94);
    let wg_v555 = eval.m31_add(wg_v553, wg_v554);
    let wg_v556 = eval.m31_mul(op0_limb_22_col66, op1_limb_27_col100);
    let wg_v557 = eval.m31_mul(op0_limb_23_col67, op1_limb_26_col99);
    let wg_v558 = eval.m31_add(wg_v556, wg_v557);
    let wg_v559 = eval.m31_mul(op0_limb_24_col68, op1_limb_25_col98);
    let wg_v560 = eval.m31_add(wg_v558, wg_v559);
    let wg_v561 = eval.m31_mul(op0_limb_25_col69, op1_limb_24_col97);
    let wg_v562 = eval.m31_add(wg_v560, wg_v561);
    let wg_v563 = eval.m31_mul(op0_limb_26_col70, op1_limb_23_col96);
    let wg_v564 = eval.m31_add(wg_v562, wg_v563);
    let wg_v565 = eval.m31_mul(op0_limb_27_col71, op1_limb_22_col95);
    let wg_v566 = eval.m31_add(wg_v564, wg_v565);
    let wg_v567 = eval.m31_mul(op0_limb_23_col67, op1_limb_27_col100);
    let wg_v568 = eval.m31_mul(op0_limb_24_col68, op1_limb_26_col99);
    let wg_v569 = eval.m31_add(wg_v567, wg_v568);
    let wg_v570 = eval.m31_mul(op0_limb_25_col69, op1_limb_25_col98);
    let wg_v571 = eval.m31_add(wg_v569, wg_v570);
    let wg_v572 = eval.m31_mul(op0_limb_26_col70, op1_limb_24_col97);
    let wg_v573 = eval.m31_add(wg_v571, wg_v572);
    let wg_v574 = eval.m31_mul(op0_limb_27_col71, op1_limb_23_col96);
    let wg_v575 = eval.m31_add(wg_v573, wg_v574);
    let wg_v576 = eval.m31_mul(op0_limb_24_col68, op1_limb_27_col100);
    let wg_v577 = eval.m31_mul(op0_limb_25_col69, op1_limb_26_col99);
    let wg_v578 = eval.m31_add(wg_v576, wg_v577);
    let wg_v579 = eval.m31_mul(op0_limb_26_col70, op1_limb_25_col98);
    let wg_v580 = eval.m31_add(wg_v578, wg_v579);
    let wg_v581 = eval.m31_mul(op0_limb_27_col71, op1_limb_24_col97);
    let wg_v582 = eval.m31_add(wg_v580, wg_v581);
    let wg_v583 = eval.m31_mul(op0_limb_25_col69, op1_limb_27_col100);
    let wg_v584 = eval.m31_mul(op0_limb_26_col70, op1_limb_26_col99);
    let wg_v585 = eval.m31_add(wg_v583, wg_v584);
    let wg_v586 = eval.m31_mul(op0_limb_27_col71, op1_limb_25_col98);
    let wg_v587 = eval.m31_add(wg_v585, wg_v586);
    let wg_v588 = eval.m31_mul(op0_limb_26_col70, op1_limb_27_col100);
    let wg_v589 = eval.m31_mul(op0_limb_27_col71, op1_limb_26_col99);
    let wg_v590 = eval.m31_add(wg_v588, wg_v589);
    let wg_v591 = eval.m31_mul(op0_limb_27_col71, op1_limb_27_col100);
    let z2_tmp_93be2_33 = [
        wg_v507, wg_v510, wg_v515, wg_v522, wg_v531, wg_v542, wg_v555, wg_v566, wg_v575, wg_v582,
        wg_v587, wg_v590, wg_v591,
    ];
    let wg_v592 = eval.m31_add(op0_limb_14_col58, op0_limb_21_col65);
    let wg_v593 = eval.m31_add(op0_limb_15_col59, op0_limb_22_col66);
    let wg_v594 = eval.m31_add(op0_limb_16_col60, op0_limb_23_col67);
    let wg_v595 = eval.m31_add(op0_limb_17_col61, op0_limb_24_col68);
    let wg_v596 = eval.m31_add(op0_limb_18_col62, op0_limb_25_col69);
    let wg_v597 = eval.m31_add(op0_limb_19_col63, op0_limb_26_col70);
    let wg_v598 = eval.m31_add(op0_limb_20_col64, op0_limb_27_col71);
    let x_sum_tmp_93be2_34 = [
        wg_v592, wg_v593, wg_v594, wg_v595, wg_v596, wg_v597, wg_v598,
    ];
    let wg_v599 = eval.m31_add(op1_limb_14_col87, op1_limb_21_col94);
    let wg_v600 = eval.m31_add(op1_limb_15_col88, op1_limb_22_col95);
    let wg_v601 = eval.m31_add(op1_limb_16_col89, op1_limb_23_col96);
    let wg_v602 = eval.m31_add(op1_limb_17_col90, op1_limb_24_col97);
    let wg_v603 = eval.m31_add(op1_limb_18_col91, op1_limb_25_col98);
    let wg_v604 = eval.m31_add(op1_limb_19_col92, op1_limb_26_col99);
    let wg_v605 = eval.m31_add(op1_limb_20_col93, op1_limb_27_col100);
    let y_sum_tmp_93be2_35 = [
        wg_v599, wg_v600, wg_v601, wg_v602, wg_v603, wg_v604, wg_v605,
    ];
    let wg_v606 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[0]);
    let wg_v607 = eval.m31_sub(wg_v606, z0_tmp_93be2_32[0]);
    let wg_v608 = eval.m31_sub(wg_v607, z2_tmp_93be2_33[0]);
    let wg_v609 = eval.m31_add(z0_tmp_93be2_32[7], wg_v608);
    let wg_v610 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[1]);
    let wg_v611 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[0]);
    let wg_v612 = eval.m31_add(wg_v610, wg_v611);
    let wg_v613 = eval.m31_sub(wg_v612, z0_tmp_93be2_32[1]);
    let wg_v614 = eval.m31_sub(wg_v613, z2_tmp_93be2_33[1]);
    let wg_v615 = eval.m31_add(z0_tmp_93be2_32[8], wg_v614);
    let wg_v616 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[2]);
    let wg_v617 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[1]);
    let wg_v618 = eval.m31_add(wg_v616, wg_v617);
    let wg_v619 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[0]);
    let wg_v620 = eval.m31_add(wg_v618, wg_v619);
    let wg_v621 = eval.m31_sub(wg_v620, z0_tmp_93be2_32[2]);
    let wg_v622 = eval.m31_sub(wg_v621, z2_tmp_93be2_33[2]);
    let wg_v623 = eval.m31_add(z0_tmp_93be2_32[9], wg_v622);
    let wg_v624 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[3]);
    let wg_v625 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[2]);
    let wg_v626 = eval.m31_add(wg_v624, wg_v625);
    let wg_v627 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[1]);
    let wg_v628 = eval.m31_add(wg_v626, wg_v627);
    let wg_v629 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[0]);
    let wg_v630 = eval.m31_add(wg_v628, wg_v629);
    let wg_v631 = eval.m31_sub(wg_v630, z0_tmp_93be2_32[3]);
    let wg_v632 = eval.m31_sub(wg_v631, z2_tmp_93be2_33[3]);
    let wg_v633 = eval.m31_add(z0_tmp_93be2_32[10], wg_v632);
    let wg_v634 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[4]);
    let wg_v635 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[3]);
    let wg_v636 = eval.m31_add(wg_v634, wg_v635);
    let wg_v637 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[2]);
    let wg_v638 = eval.m31_add(wg_v636, wg_v637);
    let wg_v639 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[1]);
    let wg_v640 = eval.m31_add(wg_v638, wg_v639);
    let wg_v641 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[0]);
    let wg_v642 = eval.m31_add(wg_v640, wg_v641);
    let wg_v643 = eval.m31_sub(wg_v642, z0_tmp_93be2_32[4]);
    let wg_v644 = eval.m31_sub(wg_v643, z2_tmp_93be2_33[4]);
    let wg_v645 = eval.m31_add(z0_tmp_93be2_32[11], wg_v644);
    let wg_v646 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[5]);
    let wg_v647 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[4]);
    let wg_v648 = eval.m31_add(wg_v646, wg_v647);
    let wg_v649 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[3]);
    let wg_v650 = eval.m31_add(wg_v648, wg_v649);
    let wg_v651 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[2]);
    let wg_v652 = eval.m31_add(wg_v650, wg_v651);
    let wg_v653 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[1]);
    let wg_v654 = eval.m31_add(wg_v652, wg_v653);
    let wg_v655 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[0]);
    let wg_v656 = eval.m31_add(wg_v654, wg_v655);
    let wg_v657 = eval.m31_sub(wg_v656, z0_tmp_93be2_32[5]);
    let wg_v658 = eval.m31_sub(wg_v657, z2_tmp_93be2_33[5]);
    let wg_v659 = eval.m31_add(z0_tmp_93be2_32[12], wg_v658);
    let wg_v660 = eval.m31_mul(x_sum_tmp_93be2_34[0], y_sum_tmp_93be2_35[6]);
    let wg_v661 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[5]);
    let wg_v662 = eval.m31_add(wg_v660, wg_v661);
    let wg_v663 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[4]);
    let wg_v664 = eval.m31_add(wg_v662, wg_v663);
    let wg_v665 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[3]);
    let wg_v666 = eval.m31_add(wg_v664, wg_v665);
    let wg_v667 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[2]);
    let wg_v668 = eval.m31_add(wg_v666, wg_v667);
    let wg_v669 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[1]);
    let wg_v670 = eval.m31_add(wg_v668, wg_v669);
    let wg_v671 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[0]);
    let wg_v672 = eval.m31_add(wg_v670, wg_v671);
    let wg_v673 = eval.m31_sub(wg_v672, z0_tmp_93be2_32[6]);
    let wg_v674 = eval.m31_sub(wg_v673, z2_tmp_93be2_33[6]);
    let wg_v675 = eval.m31_mul(x_sum_tmp_93be2_34[1], y_sum_tmp_93be2_35[6]);
    let wg_v676 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[5]);
    let wg_v677 = eval.m31_add(wg_v675, wg_v676);
    let wg_v678 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[4]);
    let wg_v679 = eval.m31_add(wg_v677, wg_v678);
    let wg_v680 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[3]);
    let wg_v681 = eval.m31_add(wg_v679, wg_v680);
    let wg_v682 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[2]);
    let wg_v683 = eval.m31_add(wg_v681, wg_v682);
    let wg_v684 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[1]);
    let wg_v685 = eval.m31_add(wg_v683, wg_v684);
    let wg_v686 = eval.m31_sub(wg_v685, z0_tmp_93be2_32[7]);
    let wg_v687 = eval.m31_sub(wg_v686, z2_tmp_93be2_33[7]);
    let wg_v688 = eval.m31_add(z2_tmp_93be2_33[0], wg_v687);
    let wg_v689 = eval.m31_mul(x_sum_tmp_93be2_34[2], y_sum_tmp_93be2_35[6]);
    let wg_v690 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[5]);
    let wg_v691 = eval.m31_add(wg_v689, wg_v690);
    let wg_v692 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[4]);
    let wg_v693 = eval.m31_add(wg_v691, wg_v692);
    let wg_v694 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[3]);
    let wg_v695 = eval.m31_add(wg_v693, wg_v694);
    let wg_v696 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[2]);
    let wg_v697 = eval.m31_add(wg_v695, wg_v696);
    let wg_v698 = eval.m31_sub(wg_v697, z0_tmp_93be2_32[8]);
    let wg_v699 = eval.m31_sub(wg_v698, z2_tmp_93be2_33[8]);
    let wg_v700 = eval.m31_add(z2_tmp_93be2_33[1], wg_v699);
    let wg_v701 = eval.m31_mul(x_sum_tmp_93be2_34[3], y_sum_tmp_93be2_35[6]);
    let wg_v702 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[5]);
    let wg_v703 = eval.m31_add(wg_v701, wg_v702);
    let wg_v704 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[4]);
    let wg_v705 = eval.m31_add(wg_v703, wg_v704);
    let wg_v706 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[3]);
    let wg_v707 = eval.m31_add(wg_v705, wg_v706);
    let wg_v708 = eval.m31_sub(wg_v707, z0_tmp_93be2_32[9]);
    let wg_v709 = eval.m31_sub(wg_v708, z2_tmp_93be2_33[9]);
    let wg_v710 = eval.m31_add(z2_tmp_93be2_33[2], wg_v709);
    let wg_v711 = eval.m31_mul(x_sum_tmp_93be2_34[4], y_sum_tmp_93be2_35[6]);
    let wg_v712 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[5]);
    let wg_v713 = eval.m31_add(wg_v711, wg_v712);
    let wg_v714 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[4]);
    let wg_v715 = eval.m31_add(wg_v713, wg_v714);
    let wg_v716 = eval.m31_sub(wg_v715, z0_tmp_93be2_32[10]);
    let wg_v717 = eval.m31_sub(wg_v716, z2_tmp_93be2_33[10]);
    let wg_v718 = eval.m31_add(z2_tmp_93be2_33[3], wg_v717);
    let wg_v719 = eval.m31_mul(x_sum_tmp_93be2_34[5], y_sum_tmp_93be2_35[6]);
    let wg_v720 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[5]);
    let wg_v721 = eval.m31_add(wg_v719, wg_v720);
    let wg_v722 = eval.m31_sub(wg_v721, z0_tmp_93be2_32[11]);
    let wg_v723 = eval.m31_sub(wg_v722, z2_tmp_93be2_33[11]);
    let wg_v724 = eval.m31_add(z2_tmp_93be2_33[4], wg_v723);
    let wg_v725 = eval.m31_mul(x_sum_tmp_93be2_34[6], y_sum_tmp_93be2_35[6]);
    let wg_v726 = eval.m31_sub(wg_v725, z0_tmp_93be2_32[12]);
    let wg_v727 = eval.m31_sub(wg_v726, z2_tmp_93be2_33[12]);
    let wg_v728 = eval.m31_add(z2_tmp_93be2_33[5], wg_v727);
    let single_karatsuba_n_7_output_tmp_93be2_36 = [
        z0_tmp_93be2_32[0],
        z0_tmp_93be2_32[1],
        z0_tmp_93be2_32[2],
        z0_tmp_93be2_32[3],
        z0_tmp_93be2_32[4],
        z0_tmp_93be2_32[5],
        z0_tmp_93be2_32[6],
        wg_v609,
        wg_v615,
        wg_v623,
        wg_v633,
        wg_v645,
        wg_v659,
        wg_v674,
        wg_v688,
        wg_v700,
        wg_v710,
        wg_v718,
        wg_v724,
        wg_v728,
        z2_tmp_93be2_33[6],
        z2_tmp_93be2_33[7],
        z2_tmp_93be2_33[8],
        z2_tmp_93be2_33[9],
        z2_tmp_93be2_33[10],
        z2_tmp_93be2_33[11],
        z2_tmp_93be2_33[12],
    ];
    let wg_v729 = eval.m31_add(op0_limb_0_col44, op0_limb_14_col58);
    let wg_v730 = eval.m31_add(op0_limb_1_col45, op0_limb_15_col59);
    let wg_v731 = eval.m31_add(op0_limb_2_col46, op0_limb_16_col60);
    let wg_v732 = eval.m31_add(op0_limb_3_col47, op0_limb_17_col61);
    let wg_v733 = eval.m31_add(op0_limb_4_col48, op0_limb_18_col62);
    let wg_v734 = eval.m31_add(op0_limb_5_col49, op0_limb_19_col63);
    let wg_v735 = eval.m31_add(op0_limb_6_col50, op0_limb_20_col64);
    let wg_v736 = eval.m31_add(op0_limb_7_col51, op0_limb_21_col65);
    let wg_v737 = eval.m31_add(op0_limb_8_col52, op0_limb_22_col66);
    let wg_v738 = eval.m31_add(op0_limb_9_col53, op0_limb_23_col67);
    let wg_v739 = eval.m31_add(op0_limb_10_col54, op0_limb_24_col68);
    let wg_v740 = eval.m31_add(op0_limb_11_col55, op0_limb_25_col69);
    let wg_v741 = eval.m31_add(op0_limb_12_col56, op0_limb_26_col70);
    let wg_v742 = eval.m31_add(op0_limb_13_col57, op0_limb_27_col71);
    let x_sum_tmp_93be2_37 = [
        wg_v729, wg_v730, wg_v731, wg_v732, wg_v733, wg_v734, wg_v735, wg_v736, wg_v737, wg_v738,
        wg_v739, wg_v740, wg_v741, wg_v742,
    ];
    let wg_v743 = eval.m31_add(op1_limb_0_col73, op1_limb_14_col87);
    let wg_v744 = eval.m31_add(op1_limb_1_col74, op1_limb_15_col88);
    let wg_v745 = eval.m31_add(op1_limb_2_col75, op1_limb_16_col89);
    let wg_v746 = eval.m31_add(op1_limb_3_col76, op1_limb_17_col90);
    let wg_v747 = eval.m31_add(op1_limb_4_col77, op1_limb_18_col91);
    let wg_v748 = eval.m31_add(op1_limb_5_col78, op1_limb_19_col92);
    let wg_v749 = eval.m31_add(op1_limb_6_col79, op1_limb_20_col93);
    let wg_v750 = eval.m31_add(op1_limb_7_col80, op1_limb_21_col94);
    let wg_v751 = eval.m31_add(op1_limb_8_col81, op1_limb_22_col95);
    let wg_v752 = eval.m31_add(op1_limb_9_col82, op1_limb_23_col96);
    let wg_v753 = eval.m31_add(op1_limb_10_col83, op1_limb_24_col97);
    let wg_v754 = eval.m31_add(op1_limb_11_col84, op1_limb_25_col98);
    let wg_v755 = eval.m31_add(op1_limb_12_col85, op1_limb_26_col99);
    let wg_v756 = eval.m31_add(op1_limb_13_col86, op1_limb_27_col100);
    let y_sum_tmp_93be2_38 = [
        wg_v743, wg_v744, wg_v745, wg_v746, wg_v747, wg_v748, wg_v749, wg_v750, wg_v751, wg_v752,
        wg_v753, wg_v754, wg_v755, wg_v756,
    ];
    let wg_v757 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[0]);
    let wg_v758 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[1]);
    let wg_v759 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[0]);
    let wg_v760 = eval.m31_add(wg_v758, wg_v759);
    let wg_v761 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[2]);
    let wg_v762 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[1]);
    let wg_v763 = eval.m31_add(wg_v761, wg_v762);
    let wg_v764 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[0]);
    let wg_v765 = eval.m31_add(wg_v763, wg_v764);
    let wg_v766 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[3]);
    let wg_v767 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[2]);
    let wg_v768 = eval.m31_add(wg_v766, wg_v767);
    let wg_v769 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[1]);
    let wg_v770 = eval.m31_add(wg_v768, wg_v769);
    let wg_v771 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[0]);
    let wg_v772 = eval.m31_add(wg_v770, wg_v771);
    let wg_v773 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[4]);
    let wg_v774 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[3]);
    let wg_v775 = eval.m31_add(wg_v773, wg_v774);
    let wg_v776 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[2]);
    let wg_v777 = eval.m31_add(wg_v775, wg_v776);
    let wg_v778 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[1]);
    let wg_v779 = eval.m31_add(wg_v777, wg_v778);
    let wg_v780 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[0]);
    let wg_v781 = eval.m31_add(wg_v779, wg_v780);
    let wg_v782 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[5]);
    let wg_v783 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[4]);
    let wg_v784 = eval.m31_add(wg_v782, wg_v783);
    let wg_v785 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[3]);
    let wg_v786 = eval.m31_add(wg_v784, wg_v785);
    let wg_v787 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[2]);
    let wg_v788 = eval.m31_add(wg_v786, wg_v787);
    let wg_v789 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[1]);
    let wg_v790 = eval.m31_add(wg_v788, wg_v789);
    let wg_v791 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[0]);
    let wg_v792 = eval.m31_add(wg_v790, wg_v791);
    let wg_v793 = eval.m31_mul(x_sum_tmp_93be2_37[0], y_sum_tmp_93be2_38[6]);
    let wg_v794 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[5]);
    let wg_v795 = eval.m31_add(wg_v793, wg_v794);
    let wg_v796 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[4]);
    let wg_v797 = eval.m31_add(wg_v795, wg_v796);
    let wg_v798 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[3]);
    let wg_v799 = eval.m31_add(wg_v797, wg_v798);
    let wg_v800 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[2]);
    let wg_v801 = eval.m31_add(wg_v799, wg_v800);
    let wg_v802 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[1]);
    let wg_v803 = eval.m31_add(wg_v801, wg_v802);
    let wg_v804 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[0]);
    let wg_v805 = eval.m31_add(wg_v803, wg_v804);
    let wg_v806 = eval.m31_mul(x_sum_tmp_93be2_37[1], y_sum_tmp_93be2_38[6]);
    let wg_v807 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[5]);
    let wg_v808 = eval.m31_add(wg_v806, wg_v807);
    let wg_v809 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[4]);
    let wg_v810 = eval.m31_add(wg_v808, wg_v809);
    let wg_v811 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[3]);
    let wg_v812 = eval.m31_add(wg_v810, wg_v811);
    let wg_v813 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[2]);
    let wg_v814 = eval.m31_add(wg_v812, wg_v813);
    let wg_v815 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[1]);
    let wg_v816 = eval.m31_add(wg_v814, wg_v815);
    let wg_v817 = eval.m31_mul(x_sum_tmp_93be2_37[2], y_sum_tmp_93be2_38[6]);
    let wg_v818 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[5]);
    let wg_v819 = eval.m31_add(wg_v817, wg_v818);
    let wg_v820 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[4]);
    let wg_v821 = eval.m31_add(wg_v819, wg_v820);
    let wg_v822 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[3]);
    let wg_v823 = eval.m31_add(wg_v821, wg_v822);
    let wg_v824 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[2]);
    let wg_v825 = eval.m31_add(wg_v823, wg_v824);
    let wg_v826 = eval.m31_mul(x_sum_tmp_93be2_37[3], y_sum_tmp_93be2_38[6]);
    let wg_v827 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[5]);
    let wg_v828 = eval.m31_add(wg_v826, wg_v827);
    let wg_v829 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[4]);
    let wg_v830 = eval.m31_add(wg_v828, wg_v829);
    let wg_v831 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[3]);
    let wg_v832 = eval.m31_add(wg_v830, wg_v831);
    let wg_v833 = eval.m31_mul(x_sum_tmp_93be2_37[4], y_sum_tmp_93be2_38[6]);
    let wg_v834 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[5]);
    let wg_v835 = eval.m31_add(wg_v833, wg_v834);
    let wg_v836 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[4]);
    let wg_v837 = eval.m31_add(wg_v835, wg_v836);
    let wg_v838 = eval.m31_mul(x_sum_tmp_93be2_37[5], y_sum_tmp_93be2_38[6]);
    let wg_v839 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[5]);
    let wg_v840 = eval.m31_add(wg_v838, wg_v839);
    let wg_v841 = eval.m31_mul(x_sum_tmp_93be2_37[6], y_sum_tmp_93be2_38[6]);
    let z0_tmp_93be2_39 = [
        wg_v757, wg_v760, wg_v765, wg_v772, wg_v781, wg_v792, wg_v805, wg_v816, wg_v825, wg_v832,
        wg_v837, wg_v840, wg_v841,
    ];
    let wg_v842 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[7]);
    let wg_v843 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[8]);
    let wg_v844 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[7]);
    let wg_v845 = eval.m31_add(wg_v843, wg_v844);
    let wg_v846 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[9]);
    let wg_v847 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[8]);
    let wg_v848 = eval.m31_add(wg_v846, wg_v847);
    let wg_v849 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[7]);
    let wg_v850 = eval.m31_add(wg_v848, wg_v849);
    let wg_v851 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[10]);
    let wg_v852 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[9]);
    let wg_v853 = eval.m31_add(wg_v851, wg_v852);
    let wg_v854 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[8]);
    let wg_v855 = eval.m31_add(wg_v853, wg_v854);
    let wg_v856 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[7]);
    let wg_v857 = eval.m31_add(wg_v855, wg_v856);
    let wg_v858 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[11]);
    let wg_v859 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[10]);
    let wg_v860 = eval.m31_add(wg_v858, wg_v859);
    let wg_v861 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[9]);
    let wg_v862 = eval.m31_add(wg_v860, wg_v861);
    let wg_v863 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[8]);
    let wg_v864 = eval.m31_add(wg_v862, wg_v863);
    let wg_v865 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[7]);
    let wg_v866 = eval.m31_add(wg_v864, wg_v865);
    let wg_v867 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[12]);
    let wg_v868 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[11]);
    let wg_v869 = eval.m31_add(wg_v867, wg_v868);
    let wg_v870 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[10]);
    let wg_v871 = eval.m31_add(wg_v869, wg_v870);
    let wg_v872 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[9]);
    let wg_v873 = eval.m31_add(wg_v871, wg_v872);
    let wg_v874 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[8]);
    let wg_v875 = eval.m31_add(wg_v873, wg_v874);
    let wg_v876 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[7]);
    let wg_v877 = eval.m31_add(wg_v875, wg_v876);
    let wg_v878 = eval.m31_mul(x_sum_tmp_93be2_37[7], y_sum_tmp_93be2_38[13]);
    let wg_v879 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[12]);
    let wg_v880 = eval.m31_add(wg_v878, wg_v879);
    let wg_v881 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[11]);
    let wg_v882 = eval.m31_add(wg_v880, wg_v881);
    let wg_v883 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[10]);
    let wg_v884 = eval.m31_add(wg_v882, wg_v883);
    let wg_v885 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[9]);
    let wg_v886 = eval.m31_add(wg_v884, wg_v885);
    let wg_v887 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[8]);
    let wg_v888 = eval.m31_add(wg_v886, wg_v887);
    let wg_v889 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[7]);
    let wg_v890 = eval.m31_add(wg_v888, wg_v889);
    let wg_v891 = eval.m31_mul(x_sum_tmp_93be2_37[8], y_sum_tmp_93be2_38[13]);
    let wg_v892 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[12]);
    let wg_v893 = eval.m31_add(wg_v891, wg_v892);
    let wg_v894 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[11]);
    let wg_v895 = eval.m31_add(wg_v893, wg_v894);
    let wg_v896 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[10]);
    let wg_v897 = eval.m31_add(wg_v895, wg_v896);
    let wg_v898 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[9]);
    let wg_v899 = eval.m31_add(wg_v897, wg_v898);
    let wg_v900 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[8]);
    let wg_v901 = eval.m31_add(wg_v899, wg_v900);
    let wg_v902 = eval.m31_mul(x_sum_tmp_93be2_37[9], y_sum_tmp_93be2_38[13]);
    let wg_v903 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[12]);
    let wg_v904 = eval.m31_add(wg_v902, wg_v903);
    let wg_v905 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[11]);
    let wg_v906 = eval.m31_add(wg_v904, wg_v905);
    let wg_v907 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[10]);
    let wg_v908 = eval.m31_add(wg_v906, wg_v907);
    let wg_v909 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[9]);
    let wg_v910 = eval.m31_add(wg_v908, wg_v909);
    let wg_v911 = eval.m31_mul(x_sum_tmp_93be2_37[10], y_sum_tmp_93be2_38[13]);
    let wg_v912 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[12]);
    let wg_v913 = eval.m31_add(wg_v911, wg_v912);
    let wg_v914 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[11]);
    let wg_v915 = eval.m31_add(wg_v913, wg_v914);
    let wg_v916 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[10]);
    let wg_v917 = eval.m31_add(wg_v915, wg_v916);
    let wg_v918 = eval.m31_mul(x_sum_tmp_93be2_37[11], y_sum_tmp_93be2_38[13]);
    let wg_v919 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[12]);
    let wg_v920 = eval.m31_add(wg_v918, wg_v919);
    let wg_v921 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[11]);
    let wg_v922 = eval.m31_add(wg_v920, wg_v921);
    let wg_v923 = eval.m31_mul(x_sum_tmp_93be2_37[12], y_sum_tmp_93be2_38[13]);
    let wg_v924 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[12]);
    let wg_v925 = eval.m31_add(wg_v923, wg_v924);
    let wg_v926 = eval.m31_mul(x_sum_tmp_93be2_37[13], y_sum_tmp_93be2_38[13]);
    let z2_tmp_93be2_40 = [
        wg_v842, wg_v845, wg_v850, wg_v857, wg_v866, wg_v877, wg_v890, wg_v901, wg_v910, wg_v917,
        wg_v922, wg_v925, wg_v926,
    ];
    let wg_v927 = eval.m31_add(x_sum_tmp_93be2_37[0], x_sum_tmp_93be2_37[7]);
    let wg_v928 = eval.m31_add(x_sum_tmp_93be2_37[1], x_sum_tmp_93be2_37[8]);
    let wg_v929 = eval.m31_add(x_sum_tmp_93be2_37[2], x_sum_tmp_93be2_37[9]);
    let wg_v930 = eval.m31_add(x_sum_tmp_93be2_37[3], x_sum_tmp_93be2_37[10]);
    let wg_v931 = eval.m31_add(x_sum_tmp_93be2_37[4], x_sum_tmp_93be2_37[11]);
    let wg_v932 = eval.m31_add(x_sum_tmp_93be2_37[5], x_sum_tmp_93be2_37[12]);
    let wg_v933 = eval.m31_add(x_sum_tmp_93be2_37[6], x_sum_tmp_93be2_37[13]);
    let x_sum_tmp_93be2_41 = [
        wg_v927, wg_v928, wg_v929, wg_v930, wg_v931, wg_v932, wg_v933,
    ];
    let wg_v934 = eval.m31_add(y_sum_tmp_93be2_38[0], y_sum_tmp_93be2_38[7]);
    let wg_v935 = eval.m31_add(y_sum_tmp_93be2_38[1], y_sum_tmp_93be2_38[8]);
    let wg_v936 = eval.m31_add(y_sum_tmp_93be2_38[2], y_sum_tmp_93be2_38[9]);
    let wg_v937 = eval.m31_add(y_sum_tmp_93be2_38[3], y_sum_tmp_93be2_38[10]);
    let wg_v938 = eval.m31_add(y_sum_tmp_93be2_38[4], y_sum_tmp_93be2_38[11]);
    let wg_v939 = eval.m31_add(y_sum_tmp_93be2_38[5], y_sum_tmp_93be2_38[12]);
    let wg_v940 = eval.m31_add(y_sum_tmp_93be2_38[6], y_sum_tmp_93be2_38[13]);
    let y_sum_tmp_93be2_42 = [
        wg_v934, wg_v935, wg_v936, wg_v937, wg_v938, wg_v939, wg_v940,
    ];
    let wg_v941 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[0]);
    let wg_v942 = eval.m31_sub(wg_v941, z0_tmp_93be2_39[0]);
    let wg_v943 = eval.m31_sub(wg_v942, z2_tmp_93be2_40[0]);
    let wg_v944 = eval.m31_add(z0_tmp_93be2_39[7], wg_v943);
    let wg_v945 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[1]);
    let wg_v946 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[0]);
    let wg_v947 = eval.m31_add(wg_v945, wg_v946);
    let wg_v948 = eval.m31_sub(wg_v947, z0_tmp_93be2_39[1]);
    let wg_v949 = eval.m31_sub(wg_v948, z2_tmp_93be2_40[1]);
    let wg_v950 = eval.m31_add(z0_tmp_93be2_39[8], wg_v949);
    let wg_v951 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[2]);
    let wg_v952 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[1]);
    let wg_v953 = eval.m31_add(wg_v951, wg_v952);
    let wg_v954 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[0]);
    let wg_v955 = eval.m31_add(wg_v953, wg_v954);
    let wg_v956 = eval.m31_sub(wg_v955, z0_tmp_93be2_39[2]);
    let wg_v957 = eval.m31_sub(wg_v956, z2_tmp_93be2_40[2]);
    let wg_v958 = eval.m31_add(z0_tmp_93be2_39[9], wg_v957);
    let wg_v959 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[3]);
    let wg_v960 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[2]);
    let wg_v961 = eval.m31_add(wg_v959, wg_v960);
    let wg_v962 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[1]);
    let wg_v963 = eval.m31_add(wg_v961, wg_v962);
    let wg_v964 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[0]);
    let wg_v965 = eval.m31_add(wg_v963, wg_v964);
    let wg_v966 = eval.m31_sub(wg_v965, z0_tmp_93be2_39[3]);
    let wg_v967 = eval.m31_sub(wg_v966, z2_tmp_93be2_40[3]);
    let wg_v968 = eval.m31_add(z0_tmp_93be2_39[10], wg_v967);
    let wg_v969 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[4]);
    let wg_v970 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[3]);
    let wg_v971 = eval.m31_add(wg_v969, wg_v970);
    let wg_v972 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[2]);
    let wg_v973 = eval.m31_add(wg_v971, wg_v972);
    let wg_v974 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[1]);
    let wg_v975 = eval.m31_add(wg_v973, wg_v974);
    let wg_v976 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[0]);
    let wg_v977 = eval.m31_add(wg_v975, wg_v976);
    let wg_v978 = eval.m31_sub(wg_v977, z0_tmp_93be2_39[4]);
    let wg_v979 = eval.m31_sub(wg_v978, z2_tmp_93be2_40[4]);
    let wg_v980 = eval.m31_add(z0_tmp_93be2_39[11], wg_v979);
    let wg_v981 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[5]);
    let wg_v982 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[4]);
    let wg_v983 = eval.m31_add(wg_v981, wg_v982);
    let wg_v984 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[3]);
    let wg_v985 = eval.m31_add(wg_v983, wg_v984);
    let wg_v986 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[2]);
    let wg_v987 = eval.m31_add(wg_v985, wg_v986);
    let wg_v988 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[1]);
    let wg_v989 = eval.m31_add(wg_v987, wg_v988);
    let wg_v990 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[0]);
    let wg_v991 = eval.m31_add(wg_v989, wg_v990);
    let wg_v992 = eval.m31_sub(wg_v991, z0_tmp_93be2_39[5]);
    let wg_v993 = eval.m31_sub(wg_v992, z2_tmp_93be2_40[5]);
    let wg_v994 = eval.m31_add(z0_tmp_93be2_39[12], wg_v993);
    let wg_v995 = eval.m31_mul(x_sum_tmp_93be2_41[0], y_sum_tmp_93be2_42[6]);
    let wg_v996 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[5]);
    let wg_v997 = eval.m31_add(wg_v995, wg_v996);
    let wg_v998 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[4]);
    let wg_v999 = eval.m31_add(wg_v997, wg_v998);
    let wg_v1000 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[3]);
    let wg_v1001 = eval.m31_add(wg_v999, wg_v1000);
    let wg_v1002 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[2]);
    let wg_v1003 = eval.m31_add(wg_v1001, wg_v1002);
    let wg_v1004 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[1]);
    let wg_v1005 = eval.m31_add(wg_v1003, wg_v1004);
    let wg_v1006 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[0]);
    let wg_v1007 = eval.m31_add(wg_v1005, wg_v1006);
    let wg_v1008 = eval.m31_sub(wg_v1007, z0_tmp_93be2_39[6]);
    let wg_v1009 = eval.m31_sub(wg_v1008, z2_tmp_93be2_40[6]);
    let wg_v1010 = eval.m31_mul(x_sum_tmp_93be2_41[1], y_sum_tmp_93be2_42[6]);
    let wg_v1011 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[5]);
    let wg_v1012 = eval.m31_add(wg_v1010, wg_v1011);
    let wg_v1013 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[4]);
    let wg_v1014 = eval.m31_add(wg_v1012, wg_v1013);
    let wg_v1015 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[3]);
    let wg_v1016 = eval.m31_add(wg_v1014, wg_v1015);
    let wg_v1017 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[2]);
    let wg_v1018 = eval.m31_add(wg_v1016, wg_v1017);
    let wg_v1019 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[1]);
    let wg_v1020 = eval.m31_add(wg_v1018, wg_v1019);
    let wg_v1021 = eval.m31_sub(wg_v1020, z0_tmp_93be2_39[7]);
    let wg_v1022 = eval.m31_sub(wg_v1021, z2_tmp_93be2_40[7]);
    let wg_v1023 = eval.m31_add(z2_tmp_93be2_40[0], wg_v1022);
    let wg_v1024 = eval.m31_mul(x_sum_tmp_93be2_41[2], y_sum_tmp_93be2_42[6]);
    let wg_v1025 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[5]);
    let wg_v1026 = eval.m31_add(wg_v1024, wg_v1025);
    let wg_v1027 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[4]);
    let wg_v1028 = eval.m31_add(wg_v1026, wg_v1027);
    let wg_v1029 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[3]);
    let wg_v1030 = eval.m31_add(wg_v1028, wg_v1029);
    let wg_v1031 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[2]);
    let wg_v1032 = eval.m31_add(wg_v1030, wg_v1031);
    let wg_v1033 = eval.m31_sub(wg_v1032, z0_tmp_93be2_39[8]);
    let wg_v1034 = eval.m31_sub(wg_v1033, z2_tmp_93be2_40[8]);
    let wg_v1035 = eval.m31_add(z2_tmp_93be2_40[1], wg_v1034);
    let wg_v1036 = eval.m31_mul(x_sum_tmp_93be2_41[3], y_sum_tmp_93be2_42[6]);
    let wg_v1037 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[5]);
    let wg_v1038 = eval.m31_add(wg_v1036, wg_v1037);
    let wg_v1039 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[4]);
    let wg_v1040 = eval.m31_add(wg_v1038, wg_v1039);
    let wg_v1041 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[3]);
    let wg_v1042 = eval.m31_add(wg_v1040, wg_v1041);
    let wg_v1043 = eval.m31_sub(wg_v1042, z0_tmp_93be2_39[9]);
    let wg_v1044 = eval.m31_sub(wg_v1043, z2_tmp_93be2_40[9]);
    let wg_v1045 = eval.m31_add(z2_tmp_93be2_40[2], wg_v1044);
    let wg_v1046 = eval.m31_mul(x_sum_tmp_93be2_41[4], y_sum_tmp_93be2_42[6]);
    let wg_v1047 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[5]);
    let wg_v1048 = eval.m31_add(wg_v1046, wg_v1047);
    let wg_v1049 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[4]);
    let wg_v1050 = eval.m31_add(wg_v1048, wg_v1049);
    let wg_v1051 = eval.m31_sub(wg_v1050, z0_tmp_93be2_39[10]);
    let wg_v1052 = eval.m31_sub(wg_v1051, z2_tmp_93be2_40[10]);
    let wg_v1053 = eval.m31_add(z2_tmp_93be2_40[3], wg_v1052);
    let wg_v1054 = eval.m31_mul(x_sum_tmp_93be2_41[5], y_sum_tmp_93be2_42[6]);
    let wg_v1055 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[5]);
    let wg_v1056 = eval.m31_add(wg_v1054, wg_v1055);
    let wg_v1057 = eval.m31_sub(wg_v1056, z0_tmp_93be2_39[11]);
    let wg_v1058 = eval.m31_sub(wg_v1057, z2_tmp_93be2_40[11]);
    let wg_v1059 = eval.m31_add(z2_tmp_93be2_40[4], wg_v1058);
    let wg_v1060 = eval.m31_mul(x_sum_tmp_93be2_41[6], y_sum_tmp_93be2_42[6]);
    let wg_v1061 = eval.m31_sub(wg_v1060, z0_tmp_93be2_39[12]);
    let wg_v1062 = eval.m31_sub(wg_v1061, z2_tmp_93be2_40[12]);
    let wg_v1063 = eval.m31_add(z2_tmp_93be2_40[5], wg_v1062);
    let single_karatsuba_n_7_output_tmp_93be2_43 = [
        z0_tmp_93be2_39[0],
        z0_tmp_93be2_39[1],
        z0_tmp_93be2_39[2],
        z0_tmp_93be2_39[3],
        z0_tmp_93be2_39[4],
        z0_tmp_93be2_39[5],
        z0_tmp_93be2_39[6],
        wg_v944,
        wg_v950,
        wg_v958,
        wg_v968,
        wg_v980,
        wg_v994,
        wg_v1009,
        wg_v1023,
        wg_v1035,
        wg_v1045,
        wg_v1053,
        wg_v1059,
        wg_v1063,
        z2_tmp_93be2_40[6],
        z2_tmp_93be2_40[7],
        z2_tmp_93be2_40[8],
        z2_tmp_93be2_40[9],
        z2_tmp_93be2_40[10],
        z2_tmp_93be2_40[11],
        z2_tmp_93be2_40[12],
    ];
    let wg_v1064 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[0],
        single_karatsuba_n_7_output_tmp_93be2_31[0],
    );
    let wg_v1065 = eval.m31_sub(wg_v1064, single_karatsuba_n_7_output_tmp_93be2_36[0]);
    let wg_v1066 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[14], wg_v1065);
    let wg_v1067 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[1],
        single_karatsuba_n_7_output_tmp_93be2_31[1],
    );
    let wg_v1068 = eval.m31_sub(wg_v1067, single_karatsuba_n_7_output_tmp_93be2_36[1]);
    let wg_v1069 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[15], wg_v1068);
    let wg_v1070 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[2],
        single_karatsuba_n_7_output_tmp_93be2_31[2],
    );
    let wg_v1071 = eval.m31_sub(wg_v1070, single_karatsuba_n_7_output_tmp_93be2_36[2]);
    let wg_v1072 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[16], wg_v1071);
    let wg_v1073 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[3],
        single_karatsuba_n_7_output_tmp_93be2_31[3],
    );
    let wg_v1074 = eval.m31_sub(wg_v1073, single_karatsuba_n_7_output_tmp_93be2_36[3]);
    let wg_v1075 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[17], wg_v1074);
    let wg_v1076 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[4],
        single_karatsuba_n_7_output_tmp_93be2_31[4],
    );
    let wg_v1077 = eval.m31_sub(wg_v1076, single_karatsuba_n_7_output_tmp_93be2_36[4]);
    let wg_v1078 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[18], wg_v1077);
    let wg_v1079 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[5],
        single_karatsuba_n_7_output_tmp_93be2_31[5],
    );
    let wg_v1080 = eval.m31_sub(wg_v1079, single_karatsuba_n_7_output_tmp_93be2_36[5]);
    let wg_v1081 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[19], wg_v1080);
    let wg_v1082 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[6],
        single_karatsuba_n_7_output_tmp_93be2_31[6],
    );
    let wg_v1083 = eval.m31_sub(wg_v1082, single_karatsuba_n_7_output_tmp_93be2_36[6]);
    let wg_v1084 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[20], wg_v1083);
    let wg_v1085 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[7],
        single_karatsuba_n_7_output_tmp_93be2_31[7],
    );
    let wg_v1086 = eval.m31_sub(wg_v1085, single_karatsuba_n_7_output_tmp_93be2_36[7]);
    let wg_v1087 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[21], wg_v1086);
    let wg_v1088 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[8],
        single_karatsuba_n_7_output_tmp_93be2_31[8],
    );
    let wg_v1089 = eval.m31_sub(wg_v1088, single_karatsuba_n_7_output_tmp_93be2_36[8]);
    let wg_v1090 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[22], wg_v1089);
    let wg_v1091 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[9],
        single_karatsuba_n_7_output_tmp_93be2_31[9],
    );
    let wg_v1092 = eval.m31_sub(wg_v1091, single_karatsuba_n_7_output_tmp_93be2_36[9]);
    let wg_v1093 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[23], wg_v1092);
    let wg_v1094 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[10],
        single_karatsuba_n_7_output_tmp_93be2_31[10],
    );
    let wg_v1095 = eval.m31_sub(wg_v1094, single_karatsuba_n_7_output_tmp_93be2_36[10]);
    let wg_v1096 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[24], wg_v1095);
    let wg_v1097 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[11],
        single_karatsuba_n_7_output_tmp_93be2_31[11],
    );
    let wg_v1098 = eval.m31_sub(wg_v1097, single_karatsuba_n_7_output_tmp_93be2_36[11]);
    let wg_v1099 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[25], wg_v1098);
    let wg_v1100 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[12],
        single_karatsuba_n_7_output_tmp_93be2_31[12],
    );
    let wg_v1101 = eval.m31_sub(wg_v1100, single_karatsuba_n_7_output_tmp_93be2_36[12]);
    let wg_v1102 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_31[26], wg_v1101);
    let wg_v1103 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[13],
        single_karatsuba_n_7_output_tmp_93be2_31[13],
    );
    let wg_v1104 = eval.m31_sub(wg_v1103, single_karatsuba_n_7_output_tmp_93be2_36[13]);
    let wg_v1105 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[14],
        single_karatsuba_n_7_output_tmp_93be2_31[14],
    );
    let wg_v1106 = eval.m31_sub(wg_v1105, single_karatsuba_n_7_output_tmp_93be2_36[14]);
    let wg_v1107 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[0], wg_v1106);
    let wg_v1108 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[15],
        single_karatsuba_n_7_output_tmp_93be2_31[15],
    );
    let wg_v1109 = eval.m31_sub(wg_v1108, single_karatsuba_n_7_output_tmp_93be2_36[15]);
    let wg_v1110 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[1], wg_v1109);
    let wg_v1111 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[16],
        single_karatsuba_n_7_output_tmp_93be2_31[16],
    );
    let wg_v1112 = eval.m31_sub(wg_v1111, single_karatsuba_n_7_output_tmp_93be2_36[16]);
    let wg_v1113 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[2], wg_v1112);
    let wg_v1114 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[17],
        single_karatsuba_n_7_output_tmp_93be2_31[17],
    );
    let wg_v1115 = eval.m31_sub(wg_v1114, single_karatsuba_n_7_output_tmp_93be2_36[17]);
    let wg_v1116 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[3], wg_v1115);
    let wg_v1117 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[18],
        single_karatsuba_n_7_output_tmp_93be2_31[18],
    );
    let wg_v1118 = eval.m31_sub(wg_v1117, single_karatsuba_n_7_output_tmp_93be2_36[18]);
    let wg_v1119 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[4], wg_v1118);
    let wg_v1120 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[19],
        single_karatsuba_n_7_output_tmp_93be2_31[19],
    );
    let wg_v1121 = eval.m31_sub(wg_v1120, single_karatsuba_n_7_output_tmp_93be2_36[19]);
    let wg_v1122 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[5], wg_v1121);
    let wg_v1123 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[20],
        single_karatsuba_n_7_output_tmp_93be2_31[20],
    );
    let wg_v1124 = eval.m31_sub(wg_v1123, single_karatsuba_n_7_output_tmp_93be2_36[20]);
    let wg_v1125 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[6], wg_v1124);
    let wg_v1126 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[21],
        single_karatsuba_n_7_output_tmp_93be2_31[21],
    );
    let wg_v1127 = eval.m31_sub(wg_v1126, single_karatsuba_n_7_output_tmp_93be2_36[21]);
    let wg_v1128 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[7], wg_v1127);
    let wg_v1129 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[22],
        single_karatsuba_n_7_output_tmp_93be2_31[22],
    );
    let wg_v1130 = eval.m31_sub(wg_v1129, single_karatsuba_n_7_output_tmp_93be2_36[22]);
    let wg_v1131 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[8], wg_v1130);
    let wg_v1132 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[23],
        single_karatsuba_n_7_output_tmp_93be2_31[23],
    );
    let wg_v1133 = eval.m31_sub(wg_v1132, single_karatsuba_n_7_output_tmp_93be2_36[23]);
    let wg_v1134 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[9], wg_v1133);
    let wg_v1135 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[24],
        single_karatsuba_n_7_output_tmp_93be2_31[24],
    );
    let wg_v1136 = eval.m31_sub(wg_v1135, single_karatsuba_n_7_output_tmp_93be2_36[24]);
    let wg_v1137 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[10], wg_v1136);
    let wg_v1138 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[25],
        single_karatsuba_n_7_output_tmp_93be2_31[25],
    );
    let wg_v1139 = eval.m31_sub(wg_v1138, single_karatsuba_n_7_output_tmp_93be2_36[25]);
    let wg_v1140 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[11], wg_v1139);
    let wg_v1141 = eval.m31_sub(
        single_karatsuba_n_7_output_tmp_93be2_43[26],
        single_karatsuba_n_7_output_tmp_93be2_31[26],
    );
    let wg_v1142 = eval.m31_sub(wg_v1141, single_karatsuba_n_7_output_tmp_93be2_36[26]);
    let wg_v1143 = eval.m31_add(single_karatsuba_n_7_output_tmp_93be2_36[12], wg_v1142);
    let double_karatsuba_f0fc6_output_tmp_93be2_44 = [
        single_karatsuba_n_7_output_tmp_93be2_31[0],
        single_karatsuba_n_7_output_tmp_93be2_31[1],
        single_karatsuba_n_7_output_tmp_93be2_31[2],
        single_karatsuba_n_7_output_tmp_93be2_31[3],
        single_karatsuba_n_7_output_tmp_93be2_31[4],
        single_karatsuba_n_7_output_tmp_93be2_31[5],
        single_karatsuba_n_7_output_tmp_93be2_31[6],
        single_karatsuba_n_7_output_tmp_93be2_31[7],
        single_karatsuba_n_7_output_tmp_93be2_31[8],
        single_karatsuba_n_7_output_tmp_93be2_31[9],
        single_karatsuba_n_7_output_tmp_93be2_31[10],
        single_karatsuba_n_7_output_tmp_93be2_31[11],
        single_karatsuba_n_7_output_tmp_93be2_31[12],
        single_karatsuba_n_7_output_tmp_93be2_31[13],
        wg_v1066,
        wg_v1069,
        wg_v1072,
        wg_v1075,
        wg_v1078,
        wg_v1081,
        wg_v1084,
        wg_v1087,
        wg_v1090,
        wg_v1093,
        wg_v1096,
        wg_v1099,
        wg_v1102,
        wg_v1104,
        wg_v1107,
        wg_v1110,
        wg_v1113,
        wg_v1116,
        wg_v1119,
        wg_v1122,
        wg_v1125,
        wg_v1128,
        wg_v1131,
        wg_v1134,
        wg_v1137,
        wg_v1140,
        wg_v1143,
        single_karatsuba_n_7_output_tmp_93be2_36[13],
        single_karatsuba_n_7_output_tmp_93be2_36[14],
        single_karatsuba_n_7_output_tmp_93be2_36[15],
        single_karatsuba_n_7_output_tmp_93be2_36[16],
        single_karatsuba_n_7_output_tmp_93be2_36[17],
        single_karatsuba_n_7_output_tmp_93be2_36[18],
        single_karatsuba_n_7_output_tmp_93be2_36[19],
        single_karatsuba_n_7_output_tmp_93be2_36[20],
        single_karatsuba_n_7_output_tmp_93be2_36[21],
        single_karatsuba_n_7_output_tmp_93be2_36[22],
        single_karatsuba_n_7_output_tmp_93be2_36[23],
        single_karatsuba_n_7_output_tmp_93be2_36[24],
        single_karatsuba_n_7_output_tmp_93be2_36[25],
        single_karatsuba_n_7_output_tmp_93be2_36[26],
    ];
    let wg_v1144 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[0],
        dst_limb_0_col15,
    );
    let wg_v1145 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[1],
        dst_limb_1_col16,
    );
    let wg_v1146 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[2],
        dst_limb_2_col17,
    );
    let wg_v1147 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[3],
        dst_limb_3_col18,
    );
    let wg_v1148 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[4],
        dst_limb_4_col19,
    );
    let wg_v1149 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[5],
        dst_limb_5_col20,
    );
    let wg_v1150 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[6],
        dst_limb_6_col21,
    );
    let wg_v1151 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[7],
        dst_limb_7_col22,
    );
    let wg_v1152 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[8],
        dst_limb_8_col23,
    );
    let wg_v1153 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[9],
        dst_limb_9_col24,
    );
    let wg_v1154 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[10],
        dst_limb_10_col25,
    );
    let wg_v1155 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[11],
        dst_limb_11_col26,
    );
    let wg_v1156 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[12],
        dst_limb_12_col27,
    );
    let wg_v1157 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[13],
        dst_limb_13_col28,
    );
    let wg_v1158 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[14],
        dst_limb_14_col29,
    );
    let wg_v1159 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[15],
        dst_limb_15_col30,
    );
    let wg_v1160 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[16],
        dst_limb_16_col31,
    );
    let wg_v1161 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[17],
        dst_limb_17_col32,
    );
    let wg_v1162 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[18],
        dst_limb_18_col33,
    );
    let wg_v1163 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[19],
        dst_limb_19_col34,
    );
    let wg_v1164 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[20],
        dst_limb_20_col35,
    );
    let wg_v1165 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[21],
        dst_limb_21_col36,
    );
    let wg_v1166 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[22],
        dst_limb_22_col37,
    );
    let wg_v1167 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[23],
        dst_limb_23_col38,
    );
    let wg_v1168 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[24],
        dst_limb_24_col39,
    );
    let wg_v1169 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[25],
        dst_limb_25_col40,
    );
    let wg_v1170 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[26],
        dst_limb_26_col41,
    );
    let wg_v1171 = eval.m31_sub(
        double_karatsuba_f0fc6_output_tmp_93be2_44[27],
        dst_limb_27_col42,
    );
    let conv_tmp_93be2_45 = [
        wg_v1144,
        wg_v1145,
        wg_v1146,
        wg_v1147,
        wg_v1148,
        wg_v1149,
        wg_v1150,
        wg_v1151,
        wg_v1152,
        wg_v1153,
        wg_v1154,
        wg_v1155,
        wg_v1156,
        wg_v1157,
        wg_v1158,
        wg_v1159,
        wg_v1160,
        wg_v1161,
        wg_v1162,
        wg_v1163,
        wg_v1164,
        wg_v1165,
        wg_v1166,
        wg_v1167,
        wg_v1168,
        wg_v1169,
        wg_v1170,
        wg_v1171,
        double_karatsuba_f0fc6_output_tmp_93be2_44[28],
        double_karatsuba_f0fc6_output_tmp_93be2_44[29],
        double_karatsuba_f0fc6_output_tmp_93be2_44[30],
        double_karatsuba_f0fc6_output_tmp_93be2_44[31],
        double_karatsuba_f0fc6_output_tmp_93be2_44[32],
        double_karatsuba_f0fc6_output_tmp_93be2_44[33],
        double_karatsuba_f0fc6_output_tmp_93be2_44[34],
        double_karatsuba_f0fc6_output_tmp_93be2_44[35],
        double_karatsuba_f0fc6_output_tmp_93be2_44[36],
        double_karatsuba_f0fc6_output_tmp_93be2_44[37],
        double_karatsuba_f0fc6_output_tmp_93be2_44[38],
        double_karatsuba_f0fc6_output_tmp_93be2_44[39],
        double_karatsuba_f0fc6_output_tmp_93be2_44[40],
        double_karatsuba_f0fc6_output_tmp_93be2_44[41],
        double_karatsuba_f0fc6_output_tmp_93be2_44[42],
        double_karatsuba_f0fc6_output_tmp_93be2_44[43],
        double_karatsuba_f0fc6_output_tmp_93be2_44[44],
        double_karatsuba_f0fc6_output_tmp_93be2_44[45],
        double_karatsuba_f0fc6_output_tmp_93be2_44[46],
        double_karatsuba_f0fc6_output_tmp_93be2_44[47],
        double_karatsuba_f0fc6_output_tmp_93be2_44[48],
        double_karatsuba_f0fc6_output_tmp_93be2_44[49],
        double_karatsuba_f0fc6_output_tmp_93be2_44[50],
        double_karatsuba_f0fc6_output_tmp_93be2_44[51],
        double_karatsuba_f0fc6_output_tmp_93be2_44[52],
        double_karatsuba_f0fc6_output_tmp_93be2_44[53],
        double_karatsuba_f0fc6_output_tmp_93be2_44[54],
    ];
    let wg_v1172 = eval.m31_mul(m31_32, conv_tmp_93be2_45[0]);
    let wg_v1173 = eval.m31_mul(m31_4, conv_tmp_93be2_45[21]);
    let wg_v1174 = eval.m31_sub(wg_v1172, wg_v1173);
    let wg_v1175 = eval.m31_mul(m31_8, conv_tmp_93be2_45[49]);
    let wg_v1176 = eval.m31_add(wg_v1174, wg_v1175);
    let wg_v1177 = eval.m31_mul(m31_32, conv_tmp_93be2_45[1]);
    let wg_v1178 = eval.m31_add(conv_tmp_93be2_45[0], wg_v1177);
    let wg_v1179 = eval.m31_mul(m31_4, conv_tmp_93be2_45[22]);
    let wg_v1180 = eval.m31_sub(wg_v1178, wg_v1179);
    let wg_v1181 = eval.m31_mul(m31_8, conv_tmp_93be2_45[50]);
    let wg_v1182 = eval.m31_add(wg_v1180, wg_v1181);
    let wg_v1183 = eval.m31_mul(m31_32, conv_tmp_93be2_45[2]);
    let wg_v1184 = eval.m31_add(conv_tmp_93be2_45[1], wg_v1183);
    let wg_v1185 = eval.m31_mul(m31_4, conv_tmp_93be2_45[23]);
    let wg_v1186 = eval.m31_sub(wg_v1184, wg_v1185);
    let wg_v1187 = eval.m31_mul(m31_8, conv_tmp_93be2_45[51]);
    let wg_v1188 = eval.m31_add(wg_v1186, wg_v1187);
    let wg_v1189 = eval.m31_mul(m31_32, conv_tmp_93be2_45[3]);
    let wg_v1190 = eval.m31_add(conv_tmp_93be2_45[2], wg_v1189);
    let wg_v1191 = eval.m31_mul(m31_4, conv_tmp_93be2_45[24]);
    let wg_v1192 = eval.m31_sub(wg_v1190, wg_v1191);
    let wg_v1193 = eval.m31_mul(m31_8, conv_tmp_93be2_45[52]);
    let wg_v1194 = eval.m31_add(wg_v1192, wg_v1193);
    let wg_v1195 = eval.m31_mul(m31_32, conv_tmp_93be2_45[4]);
    let wg_v1196 = eval.m31_add(conv_tmp_93be2_45[3], wg_v1195);
    let wg_v1197 = eval.m31_mul(m31_4, conv_tmp_93be2_45[25]);
    let wg_v1198 = eval.m31_sub(wg_v1196, wg_v1197);
    let wg_v1199 = eval.m31_mul(m31_8, conv_tmp_93be2_45[53]);
    let wg_v1200 = eval.m31_add(wg_v1198, wg_v1199);
    let wg_v1201 = eval.m31_mul(m31_32, conv_tmp_93be2_45[5]);
    let wg_v1202 = eval.m31_add(conv_tmp_93be2_45[4], wg_v1201);
    let wg_v1203 = eval.m31_mul(m31_4, conv_tmp_93be2_45[26]);
    let wg_v1204 = eval.m31_sub(wg_v1202, wg_v1203);
    let wg_v1205 = eval.m31_mul(m31_8, conv_tmp_93be2_45[54]);
    let wg_v1206 = eval.m31_add(wg_v1204, wg_v1205);
    let wg_v1207 = eval.m31_mul(m31_32, conv_tmp_93be2_45[6]);
    let wg_v1208 = eval.m31_add(conv_tmp_93be2_45[5], wg_v1207);
    let wg_v1209 = eval.m31_mul(m31_4, conv_tmp_93be2_45[27]);
    let wg_v1210 = eval.m31_sub(wg_v1208, wg_v1209);
    let wg_v1211 = eval.m31_mul(m31_2, conv_tmp_93be2_45[0]);
    let wg_v1212 = eval.m31_add(wg_v1211, conv_tmp_93be2_45[6]);
    let wg_v1213 = eval.m31_mul(m31_32, conv_tmp_93be2_45[7]);
    let wg_v1214 = eval.m31_add(wg_v1212, wg_v1213);
    let wg_v1215 = eval.m31_mul(m31_4, conv_tmp_93be2_45[28]);
    let wg_v1216 = eval.m31_sub(wg_v1214, wg_v1215);
    let wg_v1217 = eval.m31_mul(m31_2, conv_tmp_93be2_45[1]);
    let wg_v1218 = eval.m31_add(wg_v1217, conv_tmp_93be2_45[7]);
    let wg_v1219 = eval.m31_mul(m31_32, conv_tmp_93be2_45[8]);
    let wg_v1220 = eval.m31_add(wg_v1218, wg_v1219);
    let wg_v1221 = eval.m31_mul(m31_4, conv_tmp_93be2_45[29]);
    let wg_v1222 = eval.m31_sub(wg_v1220, wg_v1221);
    let wg_v1223 = eval.m31_mul(m31_2, conv_tmp_93be2_45[2]);
    let wg_v1224 = eval.m31_add(wg_v1223, conv_tmp_93be2_45[8]);
    let wg_v1225 = eval.m31_mul(m31_32, conv_tmp_93be2_45[9]);
    let wg_v1226 = eval.m31_add(wg_v1224, wg_v1225);
    let wg_v1227 = eval.m31_mul(m31_4, conv_tmp_93be2_45[30]);
    let wg_v1228 = eval.m31_sub(wg_v1226, wg_v1227);
    let wg_v1229 = eval.m31_mul(m31_2, conv_tmp_93be2_45[3]);
    let wg_v1230 = eval.m31_add(wg_v1229, conv_tmp_93be2_45[9]);
    let wg_v1231 = eval.m31_mul(m31_32, conv_tmp_93be2_45[10]);
    let wg_v1232 = eval.m31_add(wg_v1230, wg_v1231);
    let wg_v1233 = eval.m31_mul(m31_4, conv_tmp_93be2_45[31]);
    let wg_v1234 = eval.m31_sub(wg_v1232, wg_v1233);
    let wg_v1235 = eval.m31_mul(m31_2, conv_tmp_93be2_45[4]);
    let wg_v1236 = eval.m31_add(wg_v1235, conv_tmp_93be2_45[10]);
    let wg_v1237 = eval.m31_mul(m31_32, conv_tmp_93be2_45[11]);
    let wg_v1238 = eval.m31_add(wg_v1236, wg_v1237);
    let wg_v1239 = eval.m31_mul(m31_4, conv_tmp_93be2_45[32]);
    let wg_v1240 = eval.m31_sub(wg_v1238, wg_v1239);
    let wg_v1241 = eval.m31_mul(m31_2, conv_tmp_93be2_45[5]);
    let wg_v1242 = eval.m31_add(wg_v1241, conv_tmp_93be2_45[11]);
    let wg_v1243 = eval.m31_mul(m31_32, conv_tmp_93be2_45[12]);
    let wg_v1244 = eval.m31_add(wg_v1242, wg_v1243);
    let wg_v1245 = eval.m31_mul(m31_4, conv_tmp_93be2_45[33]);
    let wg_v1246 = eval.m31_sub(wg_v1244, wg_v1245);
    let wg_v1247 = eval.m31_mul(m31_2, conv_tmp_93be2_45[6]);
    let wg_v1248 = eval.m31_add(wg_v1247, conv_tmp_93be2_45[12]);
    let wg_v1249 = eval.m31_mul(m31_32, conv_tmp_93be2_45[13]);
    let wg_v1250 = eval.m31_add(wg_v1248, wg_v1249);
    let wg_v1251 = eval.m31_mul(m31_4, conv_tmp_93be2_45[34]);
    let wg_v1252 = eval.m31_sub(wg_v1250, wg_v1251);
    let wg_v1253 = eval.m31_mul(m31_2, conv_tmp_93be2_45[7]);
    let wg_v1254 = eval.m31_add(wg_v1253, conv_tmp_93be2_45[13]);
    let wg_v1255 = eval.m31_mul(m31_32, conv_tmp_93be2_45[14]);
    let wg_v1256 = eval.m31_add(wg_v1254, wg_v1255);
    let wg_v1257 = eval.m31_mul(m31_4, conv_tmp_93be2_45[35]);
    let wg_v1258 = eval.m31_sub(wg_v1256, wg_v1257);
    let wg_v1259 = eval.m31_mul(m31_2, conv_tmp_93be2_45[8]);
    let wg_v1260 = eval.m31_add(wg_v1259, conv_tmp_93be2_45[14]);
    let wg_v1261 = eval.m31_mul(m31_32, conv_tmp_93be2_45[15]);
    let wg_v1262 = eval.m31_add(wg_v1260, wg_v1261);
    let wg_v1263 = eval.m31_mul(m31_4, conv_tmp_93be2_45[36]);
    let wg_v1264 = eval.m31_sub(wg_v1262, wg_v1263);
    let wg_v1265 = eval.m31_mul(m31_2, conv_tmp_93be2_45[9]);
    let wg_v1266 = eval.m31_add(wg_v1265, conv_tmp_93be2_45[15]);
    let wg_v1267 = eval.m31_mul(m31_32, conv_tmp_93be2_45[16]);
    let wg_v1268 = eval.m31_add(wg_v1266, wg_v1267);
    let wg_v1269 = eval.m31_mul(m31_4, conv_tmp_93be2_45[37]);
    let wg_v1270 = eval.m31_sub(wg_v1268, wg_v1269);
    let wg_v1271 = eval.m31_mul(m31_2, conv_tmp_93be2_45[10]);
    let wg_v1272 = eval.m31_add(wg_v1271, conv_tmp_93be2_45[16]);
    let wg_v1273 = eval.m31_mul(m31_32, conv_tmp_93be2_45[17]);
    let wg_v1274 = eval.m31_add(wg_v1272, wg_v1273);
    let wg_v1275 = eval.m31_mul(m31_4, conv_tmp_93be2_45[38]);
    let wg_v1276 = eval.m31_sub(wg_v1274, wg_v1275);
    let wg_v1277 = eval.m31_mul(m31_2, conv_tmp_93be2_45[11]);
    let wg_v1278 = eval.m31_add(wg_v1277, conv_tmp_93be2_45[17]);
    let wg_v1279 = eval.m31_mul(m31_32, conv_tmp_93be2_45[18]);
    let wg_v1280 = eval.m31_add(wg_v1278, wg_v1279);
    let wg_v1281 = eval.m31_mul(m31_4, conv_tmp_93be2_45[39]);
    let wg_v1282 = eval.m31_sub(wg_v1280, wg_v1281);
    let wg_v1283 = eval.m31_mul(m31_2, conv_tmp_93be2_45[12]);
    let wg_v1284 = eval.m31_add(wg_v1283, conv_tmp_93be2_45[18]);
    let wg_v1285 = eval.m31_mul(m31_32, conv_tmp_93be2_45[19]);
    let wg_v1286 = eval.m31_add(wg_v1284, wg_v1285);
    let wg_v1287 = eval.m31_mul(m31_4, conv_tmp_93be2_45[40]);
    let wg_v1288 = eval.m31_sub(wg_v1286, wg_v1287);
    let wg_v1289 = eval.m31_mul(m31_2, conv_tmp_93be2_45[13]);
    let wg_v1290 = eval.m31_add(wg_v1289, conv_tmp_93be2_45[19]);
    let wg_v1291 = eval.m31_mul(m31_32, conv_tmp_93be2_45[20]);
    let wg_v1292 = eval.m31_add(wg_v1290, wg_v1291);
    let wg_v1293 = eval.m31_mul(m31_4, conv_tmp_93be2_45[41]);
    let wg_v1294 = eval.m31_sub(wg_v1292, wg_v1293);
    let wg_v1295 = eval.m31_mul(m31_2, conv_tmp_93be2_45[14]);
    let wg_v1296 = eval.m31_add(wg_v1295, conv_tmp_93be2_45[20]);
    let wg_v1297 = eval.m31_mul(m31_4, conv_tmp_93be2_45[42]);
    let wg_v1298 = eval.m31_sub(wg_v1296, wg_v1297);
    let wg_v1299 = eval.m31_mul(m31_64, conv_tmp_93be2_45[49]);
    let wg_v1300 = eval.m31_add(wg_v1298, wg_v1299);
    let wg_v1301 = eval.m31_mul(m31_2, conv_tmp_93be2_45[15]);
    let wg_v1302 = eval.m31_mul(m31_4, conv_tmp_93be2_45[43]);
    let wg_v1303 = eval.m31_sub(wg_v1301, wg_v1302);
    let wg_v1304 = eval.m31_mul(m31_2, conv_tmp_93be2_45[49]);
    let wg_v1305 = eval.m31_add(wg_v1303, wg_v1304);
    let wg_v1306 = eval.m31_mul(m31_64, conv_tmp_93be2_45[50]);
    let wg_v1307 = eval.m31_add(wg_v1305, wg_v1306);
    let wg_v1308 = eval.m31_mul(m31_2, conv_tmp_93be2_45[16]);
    let wg_v1309 = eval.m31_mul(m31_4, conv_tmp_93be2_45[44]);
    let wg_v1310 = eval.m31_sub(wg_v1308, wg_v1309);
    let wg_v1311 = eval.m31_mul(m31_2, conv_tmp_93be2_45[50]);
    let wg_v1312 = eval.m31_add(wg_v1310, wg_v1311);
    let wg_v1313 = eval.m31_mul(m31_64, conv_tmp_93be2_45[51]);
    let wg_v1314 = eval.m31_add(wg_v1312, wg_v1313);
    let wg_v1315 = eval.m31_mul(m31_2, conv_tmp_93be2_45[17]);
    let wg_v1316 = eval.m31_mul(m31_4, conv_tmp_93be2_45[45]);
    let wg_v1317 = eval.m31_sub(wg_v1315, wg_v1316);
    let wg_v1318 = eval.m31_mul(m31_2, conv_tmp_93be2_45[51]);
    let wg_v1319 = eval.m31_add(wg_v1317, wg_v1318);
    let wg_v1320 = eval.m31_mul(m31_64, conv_tmp_93be2_45[52]);
    let wg_v1321 = eval.m31_add(wg_v1319, wg_v1320);
    let wg_v1322 = eval.m31_mul(m31_2, conv_tmp_93be2_45[18]);
    let wg_v1323 = eval.m31_mul(m31_4, conv_tmp_93be2_45[46]);
    let wg_v1324 = eval.m31_sub(wg_v1322, wg_v1323);
    let wg_v1325 = eval.m31_mul(m31_2, conv_tmp_93be2_45[52]);
    let wg_v1326 = eval.m31_add(wg_v1324, wg_v1325);
    let wg_v1327 = eval.m31_mul(m31_64, conv_tmp_93be2_45[53]);
    let wg_v1328 = eval.m31_add(wg_v1326, wg_v1327);
    let wg_v1329 = eval.m31_mul(m31_2, conv_tmp_93be2_45[19]);
    let wg_v1330 = eval.m31_mul(m31_4, conv_tmp_93be2_45[47]);
    let wg_v1331 = eval.m31_sub(wg_v1329, wg_v1330);
    let wg_v1332 = eval.m31_mul(m31_2, conv_tmp_93be2_45[53]);
    let wg_v1333 = eval.m31_add(wg_v1331, wg_v1332);
    let wg_v1334 = eval.m31_mul(m31_64, conv_tmp_93be2_45[54]);
    let wg_v1335 = eval.m31_add(wg_v1333, wg_v1334);
    let wg_v1336 = eval.m31_mul(m31_2, conv_tmp_93be2_45[20]);
    let wg_v1337 = eval.m31_mul(m31_4, conv_tmp_93be2_45[48]);
    let wg_v1338 = eval.m31_sub(wg_v1336, wg_v1337);
    let wg_v1339 = eval.m31_mul(m31_2, conv_tmp_93be2_45[54]);
    let wg_v1340 = eval.m31_add(wg_v1338, wg_v1339);
    let conv_mod_tmp_93be2_46 = [
        wg_v1176, wg_v1182, wg_v1188, wg_v1194, wg_v1200, wg_v1206, wg_v1210, wg_v1216, wg_v1222,
        wg_v1228, wg_v1234, wg_v1240, wg_v1246, wg_v1252, wg_v1258, wg_v1264, wg_v1270, wg_v1276,
        wg_v1282, wg_v1288, wg_v1294, wg_v1300, wg_v1307, wg_v1314, wg_v1321, wg_v1328, wg_v1335,
        wg_v1340,
    ];
    let wg_v1341 = eval.m31_add(conv_mod_tmp_93be2_46[0], m31_134217728);
    let wg_v1342 = eval.u32_from_m31(wg_v1341);
    let wg_v1343 = eval.m31_add(conv_mod_tmp_93be2_46[1], m31_134217728);
    let wg_v1344 = eval.u32_from_m31(wg_v1343);
    let wg_v1345 = eval.u32_and_imm(wg_v1344, 511);
    let wg_v1346 = eval.u32_shl_imm(wg_v1345, 9);
    let wg_v1347 = eval.u32_add(wg_v1342, wg_v1346);
    let wg_v1348 = eval.u32_const(131072);
    let wg_v1349 = eval.u32_add(wg_v1347, wg_v1348);
    let k_mod_2_18_biased_tmp_93be2_47 = eval.u32_and_imm(wg_v1349, 262143);
    let wg_v1350 = eval.u32_low(k_mod_2_18_biased_tmp_93be2_47);
    let wg_v1351 = eval.u16_as_m31(wg_v1350);
    let wg_v1352 = eval.u32_high(k_mod_2_18_biased_tmp_93be2_47);
    let wg_v1353 = eval.u16_as_m31(wg_v1352);
    let wg_v1354 = eval.m31_sub(wg_v1353, m31_2);
    let wg_v1355 = eval.m31_mul(wg_v1354, m31_65536);
    let k_col101 = eval.m31_add(wg_v1351, wg_v1355);
    eval.set_col(101, k_col101);
    let wg_v1356 = eval.m31_add(k_col101, m31_524288);
    eval.set_sub_input_word(13, wg_v1356);
    eval.set_lookup_word(107, m31_1410849886);
    let wg_v1357 = eval.m31_add(k_col101, m31_524288);
    eval.set_lookup_word(108, wg_v1357);
    let wg_v1358 = eval.m31_sub(conv_mod_tmp_93be2_46[0], k_col101);
    let carry_0_col102 = eval.m31_mul(wg_v1358, m31_4194304);
    eval.set_col(102, carry_0_col102);
    let wg_v1359 = eval.m31_add(carry_0_col102, m31_524288);
    eval.set_sub_input_word(17, wg_v1359);
    eval.set_lookup_word(109, m31_514232941);
    let wg_v1360 = eval.m31_add(carry_0_col102, m31_524288);
    eval.set_lookup_word(110, wg_v1360);
    let wg_v1361 = eval.m31_add(conv_mod_tmp_93be2_46[1], carry_0_col102);
    let carry_1_col103 = eval.m31_mul(wg_v1361, m31_4194304);
    eval.set_col(103, carry_1_col103);
    let wg_v1362 = eval.m31_add(carry_1_col103, m31_524288);
    eval.set_sub_input_word(21, wg_v1362);
    eval.set_lookup_word(111, m31_531010560);
    let wg_v1363 = eval.m31_add(carry_1_col103, m31_524288);
    eval.set_lookup_word(112, wg_v1363);
    let wg_v1364 = eval.m31_add(conv_mod_tmp_93be2_46[2], carry_1_col103);
    let carry_2_col104 = eval.m31_mul(wg_v1364, m31_4194304);
    eval.set_col(104, carry_2_col104);
    let wg_v1365 = eval.m31_add(carry_2_col104, m31_524288);
    eval.set_sub_input_word(25, wg_v1365);
    eval.set_lookup_word(113, m31_480677703);
    let wg_v1366 = eval.m31_add(carry_2_col104, m31_524288);
    eval.set_lookup_word(114, wg_v1366);
    let wg_v1367 = eval.m31_add(conv_mod_tmp_93be2_46[3], carry_2_col104);
    let carry_3_col105 = eval.m31_mul(wg_v1367, m31_4194304);
    eval.set_col(105, carry_3_col105);
    let wg_v1368 = eval.m31_add(carry_3_col105, m31_524288);
    eval.set_sub_input_word(29, wg_v1368);
    eval.set_lookup_word(115, m31_497455322);
    let wg_v1369 = eval.m31_add(carry_3_col105, m31_524288);
    eval.set_lookup_word(116, wg_v1369);
    let wg_v1370 = eval.m31_add(conv_mod_tmp_93be2_46[4], carry_3_col105);
    let carry_4_col106 = eval.m31_mul(wg_v1370, m31_4194304);
    eval.set_col(106, carry_4_col106);
    let wg_v1371 = eval.m31_add(carry_4_col106, m31_524288);
    eval.set_sub_input_word(32, wg_v1371);
    eval.set_lookup_word(117, m31_447122465);
    let wg_v1372 = eval.m31_add(carry_4_col106, m31_524288);
    eval.set_lookup_word(118, wg_v1372);
    let wg_v1373 = eval.m31_add(conv_mod_tmp_93be2_46[5], carry_4_col106);
    let carry_5_col107 = eval.m31_mul(wg_v1373, m31_4194304);
    eval.set_col(107, carry_5_col107);
    let wg_v1374 = eval.m31_add(carry_5_col107, m31_524288);
    eval.set_sub_input_word(35, wg_v1374);
    eval.set_lookup_word(119, m31_463900084);
    let wg_v1375 = eval.m31_add(carry_5_col107, m31_524288);
    eval.set_lookup_word(120, wg_v1375);
    let wg_v1376 = eval.m31_add(conv_mod_tmp_93be2_46[6], carry_5_col107);
    let carry_6_col108 = eval.m31_mul(wg_v1376, m31_4194304);
    eval.set_col(108, carry_6_col108);
    let wg_v1377 = eval.m31_add(carry_6_col108, m31_524288);
    eval.set_sub_input_word(38, wg_v1377);
    eval.set_lookup_word(121, m31_682009131);
    let wg_v1378 = eval.m31_add(carry_6_col108, m31_524288);
    eval.set_lookup_word(122, wg_v1378);
    let wg_v1379 = eval.m31_add(conv_mod_tmp_93be2_46[7], carry_6_col108);
    let carry_7_col109 = eval.m31_mul(wg_v1379, m31_4194304);
    eval.set_col(109, carry_7_col109);
    let wg_v1380 = eval.m31_add(carry_7_col109, m31_524288);
    eval.set_sub_input_word(14, wg_v1380);
    eval.set_lookup_word(123, m31_1410849886);
    let wg_v1381 = eval.m31_add(carry_7_col109, m31_524288);
    eval.set_lookup_word(124, wg_v1381);
    let wg_v1382 = eval.m31_add(conv_mod_tmp_93be2_46[8], carry_7_col109);
    let carry_8_col110 = eval.m31_mul(wg_v1382, m31_4194304);
    eval.set_col(110, carry_8_col110);
    let wg_v1383 = eval.m31_add(carry_8_col110, m31_524288);
    eval.set_sub_input_word(18, wg_v1383);
    eval.set_lookup_word(125, m31_514232941);
    let wg_v1384 = eval.m31_add(carry_8_col110, m31_524288);
    eval.set_lookup_word(126, wg_v1384);
    let wg_v1385 = eval.m31_add(conv_mod_tmp_93be2_46[9], carry_8_col110);
    let carry_9_col111 = eval.m31_mul(wg_v1385, m31_4194304);
    eval.set_col(111, carry_9_col111);
    let wg_v1386 = eval.m31_add(carry_9_col111, m31_524288);
    eval.set_sub_input_word(22, wg_v1386);
    eval.set_lookup_word(127, m31_531010560);
    let wg_v1387 = eval.m31_add(carry_9_col111, m31_524288);
    eval.set_lookup_word(128, wg_v1387);
    let wg_v1388 = eval.m31_add(conv_mod_tmp_93be2_46[10], carry_9_col111);
    let carry_10_col112 = eval.m31_mul(wg_v1388, m31_4194304);
    eval.set_col(112, carry_10_col112);
    let wg_v1389 = eval.m31_add(carry_10_col112, m31_524288);
    eval.set_sub_input_word(26, wg_v1389);
    eval.set_lookup_word(129, m31_480677703);
    let wg_v1390 = eval.m31_add(carry_10_col112, m31_524288);
    eval.set_lookup_word(130, wg_v1390);
    let wg_v1391 = eval.m31_add(conv_mod_tmp_93be2_46[11], carry_10_col112);
    let carry_11_col113 = eval.m31_mul(wg_v1391, m31_4194304);
    eval.set_col(113, carry_11_col113);
    let wg_v1392 = eval.m31_add(carry_11_col113, m31_524288);
    eval.set_sub_input_word(30, wg_v1392);
    eval.set_lookup_word(131, m31_497455322);
    let wg_v1393 = eval.m31_add(carry_11_col113, m31_524288);
    eval.set_lookup_word(132, wg_v1393);
    let wg_v1394 = eval.m31_add(conv_mod_tmp_93be2_46[12], carry_11_col113);
    let carry_12_col114 = eval.m31_mul(wg_v1394, m31_4194304);
    eval.set_col(114, carry_12_col114);
    let wg_v1395 = eval.m31_add(carry_12_col114, m31_524288);
    eval.set_sub_input_word(33, wg_v1395);
    eval.set_lookup_word(133, m31_447122465);
    let wg_v1396 = eval.m31_add(carry_12_col114, m31_524288);
    eval.set_lookup_word(134, wg_v1396);
    let wg_v1397 = eval.m31_add(conv_mod_tmp_93be2_46[13], carry_12_col114);
    let carry_13_col115 = eval.m31_mul(wg_v1397, m31_4194304);
    eval.set_col(115, carry_13_col115);
    let wg_v1398 = eval.m31_add(carry_13_col115, m31_524288);
    eval.set_sub_input_word(36, wg_v1398);
    eval.set_lookup_word(135, m31_463900084);
    let wg_v1399 = eval.m31_add(carry_13_col115, m31_524288);
    eval.set_lookup_word(136, wg_v1399);
    let wg_v1400 = eval.m31_add(conv_mod_tmp_93be2_46[14], carry_13_col115);
    let carry_14_col116 = eval.m31_mul(wg_v1400, m31_4194304);
    eval.set_col(116, carry_14_col116);
    let wg_v1401 = eval.m31_add(carry_14_col116, m31_524288);
    eval.set_sub_input_word(39, wg_v1401);
    eval.set_lookup_word(137, m31_682009131);
    let wg_v1402 = eval.m31_add(carry_14_col116, m31_524288);
    eval.set_lookup_word(138, wg_v1402);
    let wg_v1403 = eval.m31_add(conv_mod_tmp_93be2_46[15], carry_14_col116);
    let carry_15_col117 = eval.m31_mul(wg_v1403, m31_4194304);
    eval.set_col(117, carry_15_col117);
    let wg_v1404 = eval.m31_add(carry_15_col117, m31_524288);
    eval.set_sub_input_word(15, wg_v1404);
    eval.set_lookup_word(139, m31_1410849886);
    let wg_v1405 = eval.m31_add(carry_15_col117, m31_524288);
    eval.set_lookup_word(140, wg_v1405);
    let wg_v1406 = eval.m31_add(conv_mod_tmp_93be2_46[16], carry_15_col117);
    let carry_16_col118 = eval.m31_mul(wg_v1406, m31_4194304);
    eval.set_col(118, carry_16_col118);
    let wg_v1407 = eval.m31_add(carry_16_col118, m31_524288);
    eval.set_sub_input_word(19, wg_v1407);
    eval.set_lookup_word(141, m31_514232941);
    let wg_v1408 = eval.m31_add(carry_16_col118, m31_524288);
    eval.set_lookup_word(142, wg_v1408);
    let wg_v1409 = eval.m31_add(conv_mod_tmp_93be2_46[17], carry_16_col118);
    let carry_17_col119 = eval.m31_mul(wg_v1409, m31_4194304);
    eval.set_col(119, carry_17_col119);
    let wg_v1410 = eval.m31_add(carry_17_col119, m31_524288);
    eval.set_sub_input_word(23, wg_v1410);
    eval.set_lookup_word(143, m31_531010560);
    let wg_v1411 = eval.m31_add(carry_17_col119, m31_524288);
    eval.set_lookup_word(144, wg_v1411);
    let wg_v1412 = eval.m31_add(conv_mod_tmp_93be2_46[18], carry_17_col119);
    let carry_18_col120 = eval.m31_mul(wg_v1412, m31_4194304);
    eval.set_col(120, carry_18_col120);
    let wg_v1413 = eval.m31_add(carry_18_col120, m31_524288);
    eval.set_sub_input_word(27, wg_v1413);
    eval.set_lookup_word(145, m31_480677703);
    let wg_v1414 = eval.m31_add(carry_18_col120, m31_524288);
    eval.set_lookup_word(146, wg_v1414);
    let wg_v1415 = eval.m31_add(conv_mod_tmp_93be2_46[19], carry_18_col120);
    let carry_19_col121 = eval.m31_mul(wg_v1415, m31_4194304);
    eval.set_col(121, carry_19_col121);
    let wg_v1416 = eval.m31_add(carry_19_col121, m31_524288);
    eval.set_sub_input_word(31, wg_v1416);
    eval.set_lookup_word(147, m31_497455322);
    let wg_v1417 = eval.m31_add(carry_19_col121, m31_524288);
    eval.set_lookup_word(148, wg_v1417);
    let wg_v1418 = eval.m31_add(conv_mod_tmp_93be2_46[20], carry_19_col121);
    let carry_20_col122 = eval.m31_mul(wg_v1418, m31_4194304);
    eval.set_col(122, carry_20_col122);
    let wg_v1419 = eval.m31_add(carry_20_col122, m31_524288);
    eval.set_sub_input_word(34, wg_v1419);
    eval.set_lookup_word(149, m31_447122465);
    let wg_v1420 = eval.m31_add(carry_20_col122, m31_524288);
    eval.set_lookup_word(150, wg_v1420);
    let wg_v1421 = eval.m31_mul(m31_136, k_col101);
    let wg_v1422 = eval.m31_sub(conv_mod_tmp_93be2_46[21], wg_v1421);
    let wg_v1423 = eval.m31_add(wg_v1422, carry_20_col122);
    let carry_21_col123 = eval.m31_mul(wg_v1423, m31_4194304);
    eval.set_col(123, carry_21_col123);
    let wg_v1424 = eval.m31_add(carry_21_col123, m31_524288);
    eval.set_sub_input_word(37, wg_v1424);
    eval.set_lookup_word(151, m31_463900084);
    let wg_v1425 = eval.m31_add(carry_21_col123, m31_524288);
    eval.set_lookup_word(152, wg_v1425);
    let wg_v1426 = eval.m31_add(conv_mod_tmp_93be2_46[22], carry_21_col123);
    let carry_22_col124 = eval.m31_mul(wg_v1426, m31_4194304);
    eval.set_col(124, carry_22_col124);
    let wg_v1427 = eval.m31_add(carry_22_col124, m31_524288);
    eval.set_sub_input_word(40, wg_v1427);
    eval.set_lookup_word(153, m31_682009131);
    let wg_v1428 = eval.m31_add(carry_22_col124, m31_524288);
    eval.set_lookup_word(154, wg_v1428);
    let wg_v1429 = eval.m31_add(conv_mod_tmp_93be2_46[23], carry_22_col124);
    let carry_23_col125 = eval.m31_mul(wg_v1429, m31_4194304);
    eval.set_col(125, carry_23_col125);
    let wg_v1430 = eval.m31_add(carry_23_col125, m31_524288);
    eval.set_sub_input_word(16, wg_v1430);
    eval.set_lookup_word(155, m31_1410849886);
    let wg_v1431 = eval.m31_add(carry_23_col125, m31_524288);
    eval.set_lookup_word(156, wg_v1431);
    let wg_v1432 = eval.m31_add(conv_mod_tmp_93be2_46[24], carry_23_col125);
    let carry_24_col126 = eval.m31_mul(wg_v1432, m31_4194304);
    eval.set_col(126, carry_24_col126);
    let wg_v1433 = eval.m31_add(carry_24_col126, m31_524288);
    eval.set_sub_input_word(20, wg_v1433);
    eval.set_lookup_word(157, m31_514232941);
    let wg_v1434 = eval.m31_add(carry_24_col126, m31_524288);
    eval.set_lookup_word(158, wg_v1434);
    let wg_v1435 = eval.m31_add(conv_mod_tmp_93be2_46[25], carry_24_col126);
    let carry_25_col127 = eval.m31_mul(wg_v1435, m31_4194304);
    eval.set_col(127, carry_25_col127);
    let wg_v1436 = eval.m31_add(carry_25_col127, m31_524288);
    eval.set_sub_input_word(24, wg_v1436);
    eval.set_lookup_word(159, m31_531010560);
    let wg_v1437 = eval.m31_add(carry_25_col127, m31_524288);
    eval.set_lookup_word(160, wg_v1437);
    let wg_v1438 = eval.m31_add(conv_mod_tmp_93be2_46[26], carry_25_col127);
    let carry_26_col128 = eval.m31_mul(wg_v1438, m31_4194304);
    eval.set_col(128, carry_26_col128);
    let wg_v1439 = eval.m31_add(carry_26_col128, m31_524288);
    eval.set_sub_input_word(28, wg_v1439);
    eval.set_lookup_word(161, m31_480677703);
    let wg_v1440 = eval.m31_add(carry_26_col128, m31_524288);
    eval.set_lookup_word(162, wg_v1440);
    let enabler_col129 = eval.enabler();
    eval.set_col(129, enabler_col129);
    eval.set_lookup_word(163, m31_428564188);
    eval.set_lookup_word(164, input_pc_col0);
    eval.set_lookup_word(165, input_ap_col1);
    eval.set_lookup_word(166, input_fp_col2);
    eval.set_lookup_word(167, m31_428564188);
    let wg_v1441 = eval.m31_add(input_pc_col0, m31_1);
    let wg_v1442 = eval.m31_add(wg_v1441, op1_imm_col8);
    eval.set_lookup_word(168, wg_v1442);
    let wg_v1443 = eval.m31_add(input_ap_col1, ap_update_add_1_col10);
    eval.set_lookup_word(169, wg_v1443);
    eval.set_lookup_word(170, input_fp_col2);
    eval.set_lookup_word(171, m31_1);
    eval.set_lookup_word(172, enabler_col129);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `mul_opcode_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
    range_check_20_state: &range_check_20::ClaimGenerator,
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
            |(row_index, (row, lookup_data, sub_component_inputs, mul_opcode_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    mul_opcode_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                mul_opcode_row_body(&mut eval);
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
                *lookup_data.memory_address_to_id_5 = [lw[74], lw[75], lw[76]];
                *lookup_data.memory_id_to_big_6 = [
                    lw[77], lw[78], lw[79], lw[80], lw[81], lw[82], lw[83], lw[84], lw[85], lw[86],
                    lw[87], lw[88], lw[89], lw[90], lw[91], lw[92], lw[93], lw[94], lw[95], lw[96],
                    lw[97], lw[98], lw[99], lw[100], lw[101], lw[102], lw[103], lw[104], lw[105],
                    lw[106],
                ];
                *lookup_data.range_check_20_7 = [lw[107], lw[108]];
                *lookup_data.range_check_20_b_8 = [lw[109], lw[110]];
                *lookup_data.range_check_20_c_9 = [lw[111], lw[112]];
                *lookup_data.range_check_20_d_10 = [lw[113], lw[114]];
                *lookup_data.range_check_20_e_11 = [lw[115], lw[116]];
                *lookup_data.range_check_20_f_12 = [lw[117], lw[118]];
                *lookup_data.range_check_20_g_13 = [lw[119], lw[120]];
                *lookup_data.range_check_20_h_14 = [lw[121], lw[122]];
                *lookup_data.range_check_20_15 = [lw[123], lw[124]];
                *lookup_data.range_check_20_b_16 = [lw[125], lw[126]];
                *lookup_data.range_check_20_c_17 = [lw[127], lw[128]];
                *lookup_data.range_check_20_d_18 = [lw[129], lw[130]];
                *lookup_data.range_check_20_e_19 = [lw[131], lw[132]];
                *lookup_data.range_check_20_f_20 = [lw[133], lw[134]];
                *lookup_data.range_check_20_g_21 = [lw[135], lw[136]];
                *lookup_data.range_check_20_h_22 = [lw[137], lw[138]];
                *lookup_data.range_check_20_23 = [lw[139], lw[140]];
                *lookup_data.range_check_20_b_24 = [lw[141], lw[142]];
                *lookup_data.range_check_20_c_25 = [lw[143], lw[144]];
                *lookup_data.range_check_20_d_26 = [lw[145], lw[146]];
                *lookup_data.range_check_20_e_27 = [lw[147], lw[148]];
                *lookup_data.range_check_20_f_28 = [lw[149], lw[150]];
                *lookup_data.range_check_20_g_29 = [lw[151], lw[152]];
                *lookup_data.range_check_20_h_30 = [lw[153], lw[154]];
                *lookup_data.range_check_20_31 = [lw[155], lw[156]];
                *lookup_data.range_check_20_b_32 = [lw[157], lw[158]];
                *lookup_data.range_check_20_c_33 = [lw[159], lw[160]];
                *lookup_data.range_check_20_d_34 = [lw[161], lw[162]];
                *lookup_data.opcodes_35 = [lw[163], lw[164], lw[165], lw[166]];
                *lookup_data.opcodes_36 = [lw[167], lw[168], lw[169], lw[170]];
                *lookup_data.mults_0 = lw[171];
                *lookup_data.mults_1 = lw[172];
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
                *sub_component_inputs.memory_address_to_id[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) };
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) };
                *sub_component_inputs.memory_id_to_big[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) };
                *sub_component_inputs.range_check_20[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[13]) }];
                *sub_component_inputs.range_check_20[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[14]) }];
                *sub_component_inputs.range_check_20[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[15]) }];
                *sub_component_inputs.range_check_20[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[16]) }];
                *sub_component_inputs.range_check_20_b[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[17]) }];
                *sub_component_inputs.range_check_20_b[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[18]) }];
                *sub_component_inputs.range_check_20_b[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[19]) }];
                *sub_component_inputs.range_check_20_b[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[20]) }];
                *sub_component_inputs.range_check_20_c[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[21]) }];
                *sub_component_inputs.range_check_20_c[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[22]) }];
                *sub_component_inputs.range_check_20_c[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[23]) }];
                *sub_component_inputs.range_check_20_c[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[24]) }];
                *sub_component_inputs.range_check_20_d[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[25]) }];
                *sub_component_inputs.range_check_20_d[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[26]) }];
                *sub_component_inputs.range_check_20_d[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[27]) }];
                *sub_component_inputs.range_check_20_d[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[28]) }];
                *sub_component_inputs.range_check_20_e[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[29]) }];
                *sub_component_inputs.range_check_20_e[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[30]) }];
                *sub_component_inputs.range_check_20_e[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[31]) }];
                *sub_component_inputs.range_check_20_f[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[32]) }];
                *sub_component_inputs.range_check_20_f[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[33]) }];
                *sub_component_inputs.range_check_20_f[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[34]) }];
                *sub_component_inputs.range_check_20_g[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[35]) }];
                *sub_component_inputs.range_check_20_g[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[36]) }];
                *sub_component_inputs.range_check_20_g[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[37]) }];
                *sub_component_inputs.range_check_20_h[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[38]) }];
                *sub_component_inputs.range_check_20_h[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[39]) }];
                *sub_component_inputs.range_check_20_h[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[40]) }];
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
        range_check_20_state: &range_check_20::ClaimGenerator,
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
            range_check_20_state,
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
        for inputs in sub_component_inputs.range_check_20 {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_20_b {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_20_c {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 2);
        }
        for inputs in sub_component_inputs.range_check_20_d {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 3);
        }
        for inputs in sub_component_inputs.range_check_20_e {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 4);
        }
        for inputs in sub_component_inputs.range_check_20_f {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 5);
        }
        for inputs in sub_component_inputs.range_check_20_g {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 6);
        }
        for inputs in sub_component_inputs.range_check_20_h {
            add_inputs(range_check_20_state, &inputs, inputs.len() * N_LANES, 7);
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

/// Record the `mul_opcode` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_mul_opcode() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("mul_opcode");
    mul_opcode_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    173;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    memory_address_to_id_5: 3,
    memory_id_to_big_6: 30,
    range_check_20_7: 2,
    range_check_20_b_8: 2,
    range_check_20_c_9: 2,
    range_check_20_d_10: 2,
    range_check_20_e_11: 2,
    range_check_20_f_12: 2,
    range_check_20_g_13: 2,
    range_check_20_h_14: 2,
    range_check_20_15: 2,
    range_check_20_b_16: 2,
    range_check_20_c_17: 2,
    range_check_20_d_18: 2,
    range_check_20_e_19: 2,
    range_check_20_f_20: 2,
    range_check_20_g_21: 2,
    range_check_20_h_22: 2,
    range_check_20_23: 2,
    range_check_20_b_24: 2,
    range_check_20_c_25: 2,
    range_check_20_d_26: 2,
    range_check_20_e_27: 2,
    range_check_20_f_28: 2,
    range_check_20_g_29: 2,
    range_check_20_h_30: 2,
    range_check_20_31: 2,
    range_check_20_b_32: 2,
    range_check_20_c_33: 2,
    range_check_20_d_34: 2,
    opcodes_35: 4,
    opcodes_36: 4,
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
    (
        "memory_address_to_id",
        2,
        "memory_address_to_id_state",
        0,
        9,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 10, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 11, 1),
    ("memory_id_to_big", 2, "memory_id_to_big_state", 0, 12, 1),
    ("range_check_20", 0, "range_check_20_state", 0, 13, 1),
    ("range_check_20", 1, "range_check_20_state", 0, 14, 1),
    ("range_check_20", 2, "range_check_20_state", 0, 15, 1),
    ("range_check_20", 3, "range_check_20_state", 0, 16, 1),
    ("range_check_20_b", 0, "range_check_20_state", 1, 17, 1),
    ("range_check_20_b", 1, "range_check_20_state", 1, 18, 1),
    ("range_check_20_b", 2, "range_check_20_state", 1, 19, 1),
    ("range_check_20_b", 3, "range_check_20_state", 1, 20, 1),
    ("range_check_20_c", 0, "range_check_20_state", 2, 21, 1),
    ("range_check_20_c", 1, "range_check_20_state", 2, 22, 1),
    ("range_check_20_c", 2, "range_check_20_state", 2, 23, 1),
    ("range_check_20_c", 3, "range_check_20_state", 2, 24, 1),
    ("range_check_20_d", 0, "range_check_20_state", 3, 25, 1),
    ("range_check_20_d", 1, "range_check_20_state", 3, 26, 1),
    ("range_check_20_d", 2, "range_check_20_state", 3, 27, 1),
    ("range_check_20_d", 3, "range_check_20_state", 3, 28, 1),
    ("range_check_20_e", 0, "range_check_20_state", 4, 29, 1),
    ("range_check_20_e", 1, "range_check_20_state", 4, 30, 1),
    ("range_check_20_e", 2, "range_check_20_state", 4, 31, 1),
    ("range_check_20_f", 0, "range_check_20_state", 5, 32, 1),
    ("range_check_20_f", 1, "range_check_20_state", 5, 33, 1),
    ("range_check_20_f", 2, "range_check_20_state", 5, 34, 1),
    ("range_check_20_g", 0, "range_check_20_state", 6, 35, 1),
    ("range_check_20_g", 1, "range_check_20_state", 6, 36, 1),
    ("range_check_20_g", 2, "range_check_20_state", 6, 37, 1),
    ("range_check_20_h", 0, "range_check_20_state", 7, 38, 1),
    ("range_check_20_h", 1, "range_check_20_state", 7, 39, 1),
    ("range_check_20_h", 2, "range_check_20_state", 7, 40, 1),
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
        "memory_address_to_id_5",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_6",
        "mults_0",
        false,
        "range_check_20_7",
        "mults_0",
        false,
    ),
    (
        "range_check_20_b_8",
        "mults_0",
        false,
        "range_check_20_c_9",
        "mults_0",
        false,
    ),
    (
        "range_check_20_d_10",
        "mults_0",
        false,
        "range_check_20_e_11",
        "mults_0",
        false,
    ),
    (
        "range_check_20_f_12",
        "mults_0",
        false,
        "range_check_20_g_13",
        "mults_0",
        false,
    ),
    (
        "range_check_20_h_14",
        "mults_0",
        false,
        "range_check_20_15",
        "mults_0",
        false,
    ),
    (
        "range_check_20_b_16",
        "mults_0",
        false,
        "range_check_20_c_17",
        "mults_0",
        false,
    ),
    (
        "range_check_20_d_18",
        "mults_0",
        false,
        "range_check_20_e_19",
        "mults_0",
        false,
    ),
    (
        "range_check_20_f_20",
        "mults_0",
        false,
        "range_check_20_g_21",
        "mults_0",
        false,
    ),
    (
        "range_check_20_h_22",
        "mults_0",
        false,
        "range_check_20_23",
        "mults_0",
        false,
    ),
    (
        "range_check_20_b_24",
        "mults_0",
        false,
        "range_check_20_c_25",
        "mults_0",
        false,
    ),
    (
        "range_check_20_d_26",
        "mults_0",
        false,
        "range_check_20_e_27",
        "mults_0",
        false,
    ),
    (
        "range_check_20_f_28",
        "mults_0",
        false,
        "range_check_20_g_29",
        "mults_0",
        false,
    ),
    (
        "range_check_20_h_30",
        "mults_0",
        false,
        "range_check_20_31",
        "mults_0",
        false,
    ),
    (
        "range_check_20_b_32",
        "mults_0",
        false,
        "range_check_20_c_33",
        "mults_0",
        false,
    ),
    (
        "range_check_20_d_34",
        "mults_0",
        false,
        "opcodes_35",
        "mults_1",
        false,
    ),
    ("opcodes_36", "mults_1", true, "", "", false),
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
        ld.memory_address_to_id_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_6.iter().flatten().copied().collect(),
        ld.range_check_20_7.iter().flatten().copied().collect(),
        ld.range_check_20_b_8.iter().flatten().copied().collect(),
        ld.range_check_20_c_9.iter().flatten().copied().collect(),
        ld.range_check_20_d_10.iter().flatten().copied().collect(),
        ld.range_check_20_e_11.iter().flatten().copied().collect(),
        ld.range_check_20_f_12.iter().flatten().copied().collect(),
        ld.range_check_20_g_13.iter().flatten().copied().collect(),
        ld.range_check_20_h_14.iter().flatten().copied().collect(),
        ld.range_check_20_15.iter().flatten().copied().collect(),
        ld.range_check_20_b_16.iter().flatten().copied().collect(),
        ld.range_check_20_c_17.iter().flatten().copied().collect(),
        ld.range_check_20_d_18.iter().flatten().copied().collect(),
        ld.range_check_20_e_19.iter().flatten().copied().collect(),
        ld.range_check_20_f_20.iter().flatten().copied().collect(),
        ld.range_check_20_g_21.iter().flatten().copied().collect(),
        ld.range_check_20_h_22.iter().flatten().copied().collect(),
        ld.range_check_20_23.iter().flatten().copied().collect(),
        ld.range_check_20_b_24.iter().flatten().copied().collect(),
        ld.range_check_20_c_25.iter().flatten().copied().collect(),
        ld.range_check_20_d_26.iter().flatten().copied().collect(),
        ld.range_check_20_e_27.iter().flatten().copied().collect(),
        ld.range_check_20_f_28.iter().flatten().copied().collect(),
        ld.range_check_20_g_29.iter().flatten().copied().collect(),
        ld.range_check_20_h_30.iter().flatten().copied().collect(),
        ld.range_check_20_31.iter().flatten().copied().collect(),
        ld.range_check_20_b_32.iter().flatten().copied().collect(),
        ld.range_check_20_c_33.iter().flatten().copied().collect(),
        ld.range_check_20_d_34.iter().flatten().copied().collect(),
        ld.opcodes_35.iter().flatten().copied().collect(),
        ld.opcodes_36.iter().flatten().copied().collect(),
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
        sci.memory_address_to_id[2]
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
        sci.memory_id_to_big[2]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.range_check_20[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_b[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_c[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_d[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_e[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_f[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_g[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_20_h[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
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
    range_check_20_state: &range_check_20::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
        range_check_20_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
        range_check_20_state,
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
    memory_address_to_id_5: Vec<[PackedM31; 3]>,
    memory_id_to_big_6: Vec<[PackedM31; 30]>,
    range_check_20_7: Vec<[PackedM31; 2]>,
    range_check_20_b_8: Vec<[PackedM31; 2]>,
    range_check_20_c_9: Vec<[PackedM31; 2]>,
    range_check_20_d_10: Vec<[PackedM31; 2]>,
    range_check_20_e_11: Vec<[PackedM31; 2]>,
    range_check_20_f_12: Vec<[PackedM31; 2]>,
    range_check_20_g_13: Vec<[PackedM31; 2]>,
    range_check_20_h_14: Vec<[PackedM31; 2]>,
    range_check_20_15: Vec<[PackedM31; 2]>,
    range_check_20_b_16: Vec<[PackedM31; 2]>,
    range_check_20_c_17: Vec<[PackedM31; 2]>,
    range_check_20_d_18: Vec<[PackedM31; 2]>,
    range_check_20_e_19: Vec<[PackedM31; 2]>,
    range_check_20_f_20: Vec<[PackedM31; 2]>,
    range_check_20_g_21: Vec<[PackedM31; 2]>,
    range_check_20_h_22: Vec<[PackedM31; 2]>,
    range_check_20_23: Vec<[PackedM31; 2]>,
    range_check_20_b_24: Vec<[PackedM31; 2]>,
    range_check_20_c_25: Vec<[PackedM31; 2]>,
    range_check_20_d_26: Vec<[PackedM31; 2]>,
    range_check_20_e_27: Vec<[PackedM31; 2]>,
    range_check_20_f_28: Vec<[PackedM31; 2]>,
    range_check_20_g_29: Vec<[PackedM31; 2]>,
    range_check_20_h_30: Vec<[PackedM31; 2]>,
    range_check_20_31: Vec<[PackedM31; 2]>,
    range_check_20_b_32: Vec<[PackedM31; 2]>,
    range_check_20_c_33: Vec<[PackedM31; 2]>,
    range_check_20_d_34: Vec<[PackedM31; 2]>,
    opcodes_35: Vec<[PackedM31; 4]>,
    opcodes_36: Vec<[PackedM31; 4]>,
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
    memory_address_to_id_5: 3,
    memory_id_to_big_6: 30,
    range_check_20_7: 2,
    range_check_20_b_8: 2,
    range_check_20_c_9: 2,
    range_check_20_d_10: 2,
    range_check_20_e_11: 2,
    range_check_20_f_12: 2,
    range_check_20_g_13: 2,
    range_check_20_h_14: 2,
    range_check_20_15: 2,
    range_check_20_b_16: 2,
    range_check_20_c_17: 2,
    range_check_20_d_18: 2,
    range_check_20_e_19: 2,
    range_check_20_f_20: 2,
    range_check_20_g_21: 2,
    range_check_20_h_22: 2,
    range_check_20_23: 2,
    range_check_20_b_24: 2,
    range_check_20_c_25: 2,
    range_check_20_d_26: 2,
    range_check_20_e_27: 2,
    range_check_20_f_28: 2,
    range_check_20_g_29: 2,
    range_check_20_h_30: 2,
    range_check_20_31: 2,
    range_check_20_b_32: 2,
    range_check_20_c_33: 2,
    range_check_20_d_34: 2,
    opcodes_35: 4,
    opcodes_36: 4,
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
            &self.lookup_data.memory_address_to_id_5,
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
            &self.lookup_data.memory_id_to_big_6,
            &self.lookup_data.range_check_20_7,
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
            &self.lookup_data.range_check_20_b_8,
            &self.lookup_data.range_check_20_c_9,
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
            &self.lookup_data.range_check_20_d_10,
            &self.lookup_data.range_check_20_e_11,
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
            &self.lookup_data.range_check_20_f_12,
            &self.lookup_data.range_check_20_g_13,
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
            &self.lookup_data.range_check_20_h_14,
            &self.lookup_data.range_check_20_15,
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
            &self.lookup_data.range_check_20_b_16,
            &self.lookup_data.range_check_20_c_17,
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
            &self.lookup_data.range_check_20_d_18,
            &self.lookup_data.range_check_20_e_19,
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
            &self.lookup_data.range_check_20_f_20,
            &self.lookup_data.range_check_20_g_21,
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
            &self.lookup_data.range_check_20_h_22,
            &self.lookup_data.range_check_20_23,
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
            &self.lookup_data.range_check_20_b_24,
            &self.lookup_data.range_check_20_c_25,
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
            &self.lookup_data.range_check_20_d_26,
            &self.lookup_data.range_check_20_e_27,
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
            &self.lookup_data.range_check_20_f_28,
            &self.lookup_data.range_check_20_g_29,
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
            &self.lookup_data.range_check_20_h_30,
            &self.lookup_data.range_check_20_31,
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
            &self.lookup_data.range_check_20_b_32,
            &self.lookup_data.range_check_20_c_33,
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
            &self.lookup_data.range_check_20_d_34,
            &self.lookup_data.opcodes_35,
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
            &self.lookup_data.opcodes_36,
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
