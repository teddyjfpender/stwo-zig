// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::add_opcode::{Claim, InteractionClaim, N_TRACE_COLUMNS};
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 3],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 3],
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
    let M31_128 = PackedM31::broadcast(M31::from(128));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_64 = PackedM31::broadcast(M31::from(64));
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
            |(row_index, (row, lookup_data, sub_component_inputs, add_opcode_input))| {
                let input_pc_col0 = add_opcode_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = add_opcode_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = add_opcode_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_d5af5_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_d5af5_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_d5af5_0);
                let offset0_tmp_d5af5_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_d5af5_2.as_m31();
                *row[3] = offset0_col3;
                let offset1_tmp_d5af5_3 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(1)))
                        >> (UInt16_7))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(2),
                        )) << (UInt16_2)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(3),
                        )) & (UInt16_31))
                            << (UInt16_11)));
                let offset1_col4 = offset1_tmp_d5af5_3.as_m31();
                *row[4] = offset1_col4;
                let offset2_tmp_d5af5_4 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(3)))
                        >> (UInt16_5))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(4),
                        )) << (UInt16_4)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(5),
                        )) & (UInt16_7))
                            << (UInt16_13)));
                let offset2_col5 = offset2_tmp_d5af5_4.as_m31();
                *row[5] = offset2_col5;
                let dst_base_fp_tmp_d5af5_5 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col6 = dst_base_fp_tmp_d5af5_5.as_m31();
                *row[6] = dst_base_fp_col6;
                let op0_base_fp_tmp_d5af5_6 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_1))
                        & (UInt16_1));
                let op0_base_fp_col7 = op0_base_fp_tmp_d5af5_6.as_m31();
                *row[7] = op0_base_fp_col7;
                let op1_imm_tmp_d5af5_7 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_2))
                        & (UInt16_1));
                let op1_imm_col8 = op1_imm_tmp_d5af5_7.as_m31();
                *row[8] = op1_imm_col8;
                let op1_base_fp_tmp_d5af5_8 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_3))
                        & (UInt16_1));
                let op1_base_fp_col9 = op1_base_fp_tmp_d5af5_8.as_m31();
                *row[9] = op1_base_fp_col9;
                let op1_base_ap_tmp_d5af5_9 = (((M31_1) - (op1_imm_col8)) - (op1_base_fp_col9));
                let ap_update_add_1_tmp_d5af5_10 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_d5af5_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_d5af5_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col10 = ap_update_add_1_tmp_d5af5_10.as_m31();
                *row[10] = ap_update_add_1_col10;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, offset1_col4, offset2_col5],
                    [
                        (((((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                            + ((op1_imm_col8) * (M31_32)))
                            + ((op1_base_fp_col9) * (M31_64)))
                            + ((op1_base_ap_tmp_d5af5_9) * (M31_128)))
                            + (M31_256)),
                        (((ap_update_add_1_col10) * (M31_32)) + (M31_256)),
                    ],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    offset0_col3,
                    offset1_col4,
                    offset2_col5,
                    (((((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                        + ((op1_imm_col8) * (M31_32)))
                        + ((op1_base_fp_col9) * (M31_64)))
                        + ((op1_base_ap_tmp_d5af5_9) * (M31_128)))
                        + (M31_256)),
                    (((ap_update_add_1_col10) * (M31_32)) + (M31_256)),
                    M31_0,
                ];
                let decode_instruction_7785f_output_tmp_d5af5_11 = (
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
                        op1_base_ap_tmp_d5af5_9,
                        M31_1,
                        M31_0,
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
                    + ((decode_instruction_7785f_output_tmp_d5af5_11.1[4]) * (input_ap_col1)));
                *row[13] = mem1_base_col13;

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_d5af5_12 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col11)
                            + (decode_instruction_7785f_output_tmp_d5af5_11.0[0])),
                    );
                let dst_id_col14 = memory_address_to_id_value_tmp_d5af5_12;
                *row[14] = dst_id_col14;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem_dst_base_col11) + (decode_instruction_7785f_output_tmp_d5af5_11.0[0]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem_dst_base_col11) + (decode_instruction_7785f_output_tmp_d5af5_11.0[0])),
                    dst_id_col14,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_d5af5_14 =
                    memory_id_to_big_state.deduce_output(dst_id_col14);
                let dst_limb_0_col15 = memory_id_to_big_value_tmp_d5af5_14.get_m31(0);
                *row[15] = dst_limb_0_col15;
                let dst_limb_1_col16 = memory_id_to_big_value_tmp_d5af5_14.get_m31(1);
                *row[16] = dst_limb_1_col16;
                let dst_limb_2_col17 = memory_id_to_big_value_tmp_d5af5_14.get_m31(2);
                *row[17] = dst_limb_2_col17;
                let dst_limb_3_col18 = memory_id_to_big_value_tmp_d5af5_14.get_m31(3);
                *row[18] = dst_limb_3_col18;
                let dst_limb_4_col19 = memory_id_to_big_value_tmp_d5af5_14.get_m31(4);
                *row[19] = dst_limb_4_col19;
                let dst_limb_5_col20 = memory_id_to_big_value_tmp_d5af5_14.get_m31(5);
                *row[20] = dst_limb_5_col20;
                let dst_limb_6_col21 = memory_id_to_big_value_tmp_d5af5_14.get_m31(6);
                *row[21] = dst_limb_6_col21;
                let dst_limb_7_col22 = memory_id_to_big_value_tmp_d5af5_14.get_m31(7);
                *row[22] = dst_limb_7_col22;
                let dst_limb_8_col23 = memory_id_to_big_value_tmp_d5af5_14.get_m31(8);
                *row[23] = dst_limb_8_col23;
                let dst_limb_9_col24 = memory_id_to_big_value_tmp_d5af5_14.get_m31(9);
                *row[24] = dst_limb_9_col24;
                let dst_limb_10_col25 = memory_id_to_big_value_tmp_d5af5_14.get_m31(10);
                *row[25] = dst_limb_10_col25;
                let dst_limb_11_col26 = memory_id_to_big_value_tmp_d5af5_14.get_m31(11);
                *row[26] = dst_limb_11_col26;
                let dst_limb_12_col27 = memory_id_to_big_value_tmp_d5af5_14.get_m31(12);
                *row[27] = dst_limb_12_col27;
                let dst_limb_13_col28 = memory_id_to_big_value_tmp_d5af5_14.get_m31(13);
                *row[28] = dst_limb_13_col28;
                let dst_limb_14_col29 = memory_id_to_big_value_tmp_d5af5_14.get_m31(14);
                *row[29] = dst_limb_14_col29;
                let dst_limb_15_col30 = memory_id_to_big_value_tmp_d5af5_14.get_m31(15);
                *row[30] = dst_limb_15_col30;
                let dst_limb_16_col31 = memory_id_to_big_value_tmp_d5af5_14.get_m31(16);
                *row[31] = dst_limb_16_col31;
                let dst_limb_17_col32 = memory_id_to_big_value_tmp_d5af5_14.get_m31(17);
                *row[32] = dst_limb_17_col32;
                let dst_limb_18_col33 = memory_id_to_big_value_tmp_d5af5_14.get_m31(18);
                *row[33] = dst_limb_18_col33;
                let dst_limb_19_col34 = memory_id_to_big_value_tmp_d5af5_14.get_m31(19);
                *row[34] = dst_limb_19_col34;
                let dst_limb_20_col35 = memory_id_to_big_value_tmp_d5af5_14.get_m31(20);
                *row[35] = dst_limb_20_col35;
                let dst_limb_21_col36 = memory_id_to_big_value_tmp_d5af5_14.get_m31(21);
                *row[36] = dst_limb_21_col36;
                let dst_limb_22_col37 = memory_id_to_big_value_tmp_d5af5_14.get_m31(22);
                *row[37] = dst_limb_22_col37;
                let dst_limb_23_col38 = memory_id_to_big_value_tmp_d5af5_14.get_m31(23);
                *row[38] = dst_limb_23_col38;
                let dst_limb_24_col39 = memory_id_to_big_value_tmp_d5af5_14.get_m31(24);
                *row[39] = dst_limb_24_col39;
                let dst_limb_25_col40 = memory_id_to_big_value_tmp_d5af5_14.get_m31(25);
                *row[40] = dst_limb_25_col40;
                let dst_limb_26_col41 = memory_id_to_big_value_tmp_d5af5_14.get_m31(26);
                *row[41] = dst_limb_26_col41;
                let dst_limb_27_col42 = memory_id_to_big_value_tmp_d5af5_14.get_m31(27);
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
                let read_positive_known_id_num_bits_252_output_tmp_d5af5_15 =
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

                let read_positive_num_bits_252_output_tmp_d5af5_16 = (
                    read_positive_known_id_num_bits_252_output_tmp_d5af5_15,
                    dst_id_col14,
                );

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_d5af5_17 = memory_address_to_id_state
                    .deduce_output(
                        ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_d5af5_11.0[1])),
                    );
                let op0_id_col43 = memory_address_to_id_value_tmp_d5af5_17;
                *row[43] = op0_id_col43;
                *sub_component_inputs.memory_address_to_id[1] =
                    ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_d5af5_11.0[1]));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_d5af5_11.0[1])),
                    op0_id_col43,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_d5af5_19 =
                    memory_id_to_big_state.deduce_output(op0_id_col43);
                let op0_limb_0_col44 = memory_id_to_big_value_tmp_d5af5_19.get_m31(0);
                *row[44] = op0_limb_0_col44;
                let op0_limb_1_col45 = memory_id_to_big_value_tmp_d5af5_19.get_m31(1);
                *row[45] = op0_limb_1_col45;
                let op0_limb_2_col46 = memory_id_to_big_value_tmp_d5af5_19.get_m31(2);
                *row[46] = op0_limb_2_col46;
                let op0_limb_3_col47 = memory_id_to_big_value_tmp_d5af5_19.get_m31(3);
                *row[47] = op0_limb_3_col47;
                let op0_limb_4_col48 = memory_id_to_big_value_tmp_d5af5_19.get_m31(4);
                *row[48] = op0_limb_4_col48;
                let op0_limb_5_col49 = memory_id_to_big_value_tmp_d5af5_19.get_m31(5);
                *row[49] = op0_limb_5_col49;
                let op0_limb_6_col50 = memory_id_to_big_value_tmp_d5af5_19.get_m31(6);
                *row[50] = op0_limb_6_col50;
                let op0_limb_7_col51 = memory_id_to_big_value_tmp_d5af5_19.get_m31(7);
                *row[51] = op0_limb_7_col51;
                let op0_limb_8_col52 = memory_id_to_big_value_tmp_d5af5_19.get_m31(8);
                *row[52] = op0_limb_8_col52;
                let op0_limb_9_col53 = memory_id_to_big_value_tmp_d5af5_19.get_m31(9);
                *row[53] = op0_limb_9_col53;
                let op0_limb_10_col54 = memory_id_to_big_value_tmp_d5af5_19.get_m31(10);
                *row[54] = op0_limb_10_col54;
                let op0_limb_11_col55 = memory_id_to_big_value_tmp_d5af5_19.get_m31(11);
                *row[55] = op0_limb_11_col55;
                let op0_limb_12_col56 = memory_id_to_big_value_tmp_d5af5_19.get_m31(12);
                *row[56] = op0_limb_12_col56;
                let op0_limb_13_col57 = memory_id_to_big_value_tmp_d5af5_19.get_m31(13);
                *row[57] = op0_limb_13_col57;
                let op0_limb_14_col58 = memory_id_to_big_value_tmp_d5af5_19.get_m31(14);
                *row[58] = op0_limb_14_col58;
                let op0_limb_15_col59 = memory_id_to_big_value_tmp_d5af5_19.get_m31(15);
                *row[59] = op0_limb_15_col59;
                let op0_limb_16_col60 = memory_id_to_big_value_tmp_d5af5_19.get_m31(16);
                *row[60] = op0_limb_16_col60;
                let op0_limb_17_col61 = memory_id_to_big_value_tmp_d5af5_19.get_m31(17);
                *row[61] = op0_limb_17_col61;
                let op0_limb_18_col62 = memory_id_to_big_value_tmp_d5af5_19.get_m31(18);
                *row[62] = op0_limb_18_col62;
                let op0_limb_19_col63 = memory_id_to_big_value_tmp_d5af5_19.get_m31(19);
                *row[63] = op0_limb_19_col63;
                let op0_limb_20_col64 = memory_id_to_big_value_tmp_d5af5_19.get_m31(20);
                *row[64] = op0_limb_20_col64;
                let op0_limb_21_col65 = memory_id_to_big_value_tmp_d5af5_19.get_m31(21);
                *row[65] = op0_limb_21_col65;
                let op0_limb_22_col66 = memory_id_to_big_value_tmp_d5af5_19.get_m31(22);
                *row[66] = op0_limb_22_col66;
                let op0_limb_23_col67 = memory_id_to_big_value_tmp_d5af5_19.get_m31(23);
                *row[67] = op0_limb_23_col67;
                let op0_limb_24_col68 = memory_id_to_big_value_tmp_d5af5_19.get_m31(24);
                *row[68] = op0_limb_24_col68;
                let op0_limb_25_col69 = memory_id_to_big_value_tmp_d5af5_19.get_m31(25);
                *row[69] = op0_limb_25_col69;
                let op0_limb_26_col70 = memory_id_to_big_value_tmp_d5af5_19.get_m31(26);
                *row[70] = op0_limb_26_col70;
                let op0_limb_27_col71 = memory_id_to_big_value_tmp_d5af5_19.get_m31(27);
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
                let read_positive_known_id_num_bits_252_output_tmp_d5af5_20 =
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

                let read_positive_num_bits_252_output_tmp_d5af5_21 = (
                    read_positive_known_id_num_bits_252_output_tmp_d5af5_20,
                    op0_id_col43,
                );

                // Read Positive Num Bits 252.

                // Read Id.

                let memory_address_to_id_value_tmp_d5af5_22 = memory_address_to_id_state
                    .deduce_output(
                        ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_d5af5_11.0[2])),
                    );
                let op1_id_col72 = memory_address_to_id_value_tmp_d5af5_22;
                *row[72] = op1_id_col72;
                *sub_component_inputs.memory_address_to_id[2] =
                    ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_d5af5_11.0[2]));
                *lookup_data.memory_address_to_id_5 = [
                    M31_1444891767,
                    ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_d5af5_11.0[2])),
                    op1_id_col72,
                ];

                // Read Positive Known Id Num Bits 252.

                let memory_id_to_big_value_tmp_d5af5_24 =
                    memory_id_to_big_state.deduce_output(op1_id_col72);
                let op1_limb_0_col73 = memory_id_to_big_value_tmp_d5af5_24.get_m31(0);
                *row[73] = op1_limb_0_col73;
                let op1_limb_1_col74 = memory_id_to_big_value_tmp_d5af5_24.get_m31(1);
                *row[74] = op1_limb_1_col74;
                let op1_limb_2_col75 = memory_id_to_big_value_tmp_d5af5_24.get_m31(2);
                *row[75] = op1_limb_2_col75;
                let op1_limb_3_col76 = memory_id_to_big_value_tmp_d5af5_24.get_m31(3);
                *row[76] = op1_limb_3_col76;
                let op1_limb_4_col77 = memory_id_to_big_value_tmp_d5af5_24.get_m31(4);
                *row[77] = op1_limb_4_col77;
                let op1_limb_5_col78 = memory_id_to_big_value_tmp_d5af5_24.get_m31(5);
                *row[78] = op1_limb_5_col78;
                let op1_limb_6_col79 = memory_id_to_big_value_tmp_d5af5_24.get_m31(6);
                *row[79] = op1_limb_6_col79;
                let op1_limb_7_col80 = memory_id_to_big_value_tmp_d5af5_24.get_m31(7);
                *row[80] = op1_limb_7_col80;
                let op1_limb_8_col81 = memory_id_to_big_value_tmp_d5af5_24.get_m31(8);
                *row[81] = op1_limb_8_col81;
                let op1_limb_9_col82 = memory_id_to_big_value_tmp_d5af5_24.get_m31(9);
                *row[82] = op1_limb_9_col82;
                let op1_limb_10_col83 = memory_id_to_big_value_tmp_d5af5_24.get_m31(10);
                *row[83] = op1_limb_10_col83;
                let op1_limb_11_col84 = memory_id_to_big_value_tmp_d5af5_24.get_m31(11);
                *row[84] = op1_limb_11_col84;
                let op1_limb_12_col85 = memory_id_to_big_value_tmp_d5af5_24.get_m31(12);
                *row[85] = op1_limb_12_col85;
                let op1_limb_13_col86 = memory_id_to_big_value_tmp_d5af5_24.get_m31(13);
                *row[86] = op1_limb_13_col86;
                let op1_limb_14_col87 = memory_id_to_big_value_tmp_d5af5_24.get_m31(14);
                *row[87] = op1_limb_14_col87;
                let op1_limb_15_col88 = memory_id_to_big_value_tmp_d5af5_24.get_m31(15);
                *row[88] = op1_limb_15_col88;
                let op1_limb_16_col89 = memory_id_to_big_value_tmp_d5af5_24.get_m31(16);
                *row[89] = op1_limb_16_col89;
                let op1_limb_17_col90 = memory_id_to_big_value_tmp_d5af5_24.get_m31(17);
                *row[90] = op1_limb_17_col90;
                let op1_limb_18_col91 = memory_id_to_big_value_tmp_d5af5_24.get_m31(18);
                *row[91] = op1_limb_18_col91;
                let op1_limb_19_col92 = memory_id_to_big_value_tmp_d5af5_24.get_m31(19);
                *row[92] = op1_limb_19_col92;
                let op1_limb_20_col93 = memory_id_to_big_value_tmp_d5af5_24.get_m31(20);
                *row[93] = op1_limb_20_col93;
                let op1_limb_21_col94 = memory_id_to_big_value_tmp_d5af5_24.get_m31(21);
                *row[94] = op1_limb_21_col94;
                let op1_limb_22_col95 = memory_id_to_big_value_tmp_d5af5_24.get_m31(22);
                *row[95] = op1_limb_22_col95;
                let op1_limb_23_col96 = memory_id_to_big_value_tmp_d5af5_24.get_m31(23);
                *row[96] = op1_limb_23_col96;
                let op1_limb_24_col97 = memory_id_to_big_value_tmp_d5af5_24.get_m31(24);
                *row[97] = op1_limb_24_col97;
                let op1_limb_25_col98 = memory_id_to_big_value_tmp_d5af5_24.get_m31(25);
                *row[98] = op1_limb_25_col98;
                let op1_limb_26_col99 = memory_id_to_big_value_tmp_d5af5_24.get_m31(26);
                *row[99] = op1_limb_26_col99;
                let op1_limb_27_col100 = memory_id_to_big_value_tmp_d5af5_24.get_m31(27);
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
                let read_positive_known_id_num_bits_252_output_tmp_d5af5_25 =
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

                let read_positive_num_bits_252_output_tmp_d5af5_26 = (
                    read_positive_known_id_num_bits_252_output_tmp_d5af5_25,
                    op1_id_col72,
                );

                // Verify Add 252.

                let sub_p_bit_tmp_d5af5_27 = ((UInt16_1)
                    & (((PackedUInt16::from_m31(op0_limb_0_col44))
                        ^ (PackedUInt16::from_m31(op1_limb_0_col73)))
                        ^ (PackedUInt16::from_m31(dst_limb_0_col15))));
                let sub_p_bit_col101 = sub_p_bit_tmp_d5af5_27.as_m31();
                *row[101] = sub_p_bit_col101;

                let enabler_col102 = enabler_col.packed_at(row_index);
                *row[102] = enabler_col102;
                *lookup_data.opcodes_7 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_8 = [
                    M31_428564188,
                    (((input_pc_col0) + (M31_1)) + (op1_imm_col8)),
                    ((input_ap_col1) + (ap_update_add_1_col10)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col102;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `add_opcode` — mechanical rewrite of
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
//     opcodes_7[4] 107..110
//     opcodes_8[4] 111..114
//     mults_0 115
//     mults_1 116
//     (117 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     memory_address_to_id[2] 9
//     memory_id_to_big[0] 10
//     memory_id_to_big[1] 11
//     memory_id_to_big[2] 12
//     (13 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 117;
pub(crate) const N_SUB_INPUT_WORDS: usize = 13;

/// The per-row `add_opcode` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn add_opcode_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_8 = eval.m31_const(8);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_128 = eval.m31_const(128);
    let m31_256 = eval.m31_const(256);
    let m31_32768 = eval.m31_const(32768);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_d5af5_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_d5af5_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_d5af5_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_d5af5_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_d5af5_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 1);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 7);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 2);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 2);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 3);
    let wg_v14 = eval.u16_from_m31(wg_v13);
    let wg_v15 = eval.u16_and(wg_v14, 31);
    let wg_v16 = eval.u16_shl(wg_v15, 11);
    let offset1_tmp_d5af5_3 = eval.u16_add(wg_v12, wg_v16);
    let offset1_col4 = eval.u16_as_m31(offset1_tmp_d5af5_3);
    eval.set_col(4, offset1_col4);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 3);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shr(wg_v18, 5);
    let wg_v20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 4);
    let wg_v21 = eval.u16_from_m31(wg_v20);
    let wg_v22 = eval.u16_shl(wg_v21, 4);
    let wg_v23 = eval.u16_add(wg_v19, wg_v22);
    let wg_v24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v25 = eval.u16_from_m31(wg_v24);
    let wg_v26 = eval.u16_and(wg_v25, 7);
    let wg_v27 = eval.u16_shl(wg_v26, 13);
    let offset2_tmp_d5af5_4 = eval.u16_add(wg_v23, wg_v27);
    let offset2_col5 = eval.u16_as_m31(offset2_tmp_d5af5_4);
    eval.set_col(5, offset2_col5);
    let wg_v28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v29 = eval.u16_from_m31(wg_v28);
    let wg_v30 = eval.u16_shr(wg_v29, 3);
    let wg_v31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 6);
    let wg_v32 = eval.u16_from_m31(wg_v31);
    let wg_v33 = eval.u16_shl(wg_v32, 6);
    let wg_v34 = eval.u16_add(wg_v30, wg_v33);
    let wg_v35 = eval.u16_shr(wg_v34, 0);
    let dst_base_fp_tmp_d5af5_5 = eval.u16_and(wg_v35, 1);
    let dst_base_fp_col6 = eval.u16_as_m31(dst_base_fp_tmp_d5af5_5);
    eval.set_col(6, dst_base_fp_col6);
    let wg_v36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v37 = eval.u16_from_m31(wg_v36);
    let wg_v38 = eval.u16_shr(wg_v37, 3);
    let wg_v39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 6);
    let wg_v40 = eval.u16_from_m31(wg_v39);
    let wg_v41 = eval.u16_shl(wg_v40, 6);
    let wg_v42 = eval.u16_add(wg_v38, wg_v41);
    let wg_v43 = eval.u16_shr(wg_v42, 1);
    let op0_base_fp_tmp_d5af5_6 = eval.u16_and(wg_v43, 1);
    let op0_base_fp_col7 = eval.u16_as_m31(op0_base_fp_tmp_d5af5_6);
    eval.set_col(7, op0_base_fp_col7);
    let wg_v44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v45 = eval.u16_from_m31(wg_v44);
    let wg_v46 = eval.u16_shr(wg_v45, 3);
    let wg_v47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 6);
    let wg_v48 = eval.u16_from_m31(wg_v47);
    let wg_v49 = eval.u16_shl(wg_v48, 6);
    let wg_v50 = eval.u16_add(wg_v46, wg_v49);
    let wg_v51 = eval.u16_shr(wg_v50, 2);
    let op1_imm_tmp_d5af5_7 = eval.u16_and(wg_v51, 1);
    let op1_imm_col8 = eval.u16_as_m31(op1_imm_tmp_d5af5_7);
    eval.set_col(8, op1_imm_col8);
    let wg_v52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v53 = eval.u16_from_m31(wg_v52);
    let wg_v54 = eval.u16_shr(wg_v53, 3);
    let wg_v55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 6);
    let wg_v56 = eval.u16_from_m31(wg_v55);
    let wg_v57 = eval.u16_shl(wg_v56, 6);
    let wg_v58 = eval.u16_add(wg_v54, wg_v57);
    let wg_v59 = eval.u16_shr(wg_v58, 3);
    let op1_base_fp_tmp_d5af5_8 = eval.u16_and(wg_v59, 1);
    let op1_base_fp_col9 = eval.u16_as_m31(op1_base_fp_tmp_d5af5_8);
    eval.set_col(9, op1_base_fp_col9);
    let wg_v60 = eval.m31_sub(m31_1, op1_imm_col8);
    let op1_base_ap_tmp_d5af5_9 = eval.m31_sub(wg_v60, op1_base_fp_col9);
    let wg_v61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 5);
    let wg_v62 = eval.u16_from_m31(wg_v61);
    let wg_v63 = eval.u16_shr(wg_v62, 3);
    let wg_v64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_1.clone(), 6);
    let wg_v65 = eval.u16_from_m31(wg_v64);
    let wg_v66 = eval.u16_shl(wg_v65, 6);
    let wg_v67 = eval.u16_add(wg_v63, wg_v66);
    let wg_v68 = eval.u16_shr(wg_v67, 11);
    let ap_update_add_1_tmp_d5af5_10 = eval.u16_and(wg_v68, 1);
    let ap_update_add_1_col10 = eval.u16_as_m31(ap_update_add_1_tmp_d5af5_10);
    eval.set_col(10, ap_update_add_1_col10);
    let wg_v69 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v70 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v71 = eval.m31_add(wg_v69, wg_v70);
    let wg_v72 = eval.m31_mul(op1_imm_col8, m31_32);
    let wg_v73 = eval.m31_add(wg_v71, wg_v72);
    let wg_v74 = eval.m31_mul(op1_base_fp_col9, m31_64);
    let wg_v75 = eval.m31_add(wg_v73, wg_v74);
    let wg_v76 = eval.m31_mul(op1_base_ap_tmp_d5af5_9, m31_128);
    let wg_v77 = eval.m31_add(wg_v75, wg_v76);
    let wg_v78 = eval.m31_add(wg_v77, m31_256);
    let wg_v79 = eval.m31_mul(ap_update_add_1_col10, m31_32);
    let wg_v80 = eval.m31_add(wg_v79, m31_256);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, offset0_col3);
    eval.set_sub_input_word(2, offset1_col4);
    eval.set_sub_input_word(3, offset2_col5);
    eval.set_sub_input_word(4, wg_v78);
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
    let wg_v88 = eval.m31_mul(op1_base_ap_tmp_d5af5_9, m31_128);
    let wg_v89 = eval.m31_add(wg_v87, wg_v88);
    let wg_v90 = eval.m31_add(wg_v89, m31_256);
    eval.set_lookup_word(5, wg_v90);
    let wg_v91 = eval.m31_mul(ap_update_add_1_col10, m31_32);
    let wg_v92 = eval.m31_add(wg_v91, m31_256);
    eval.set_lookup_word(6, wg_v92);
    eval.set_lookup_word(7, m31_0);
    let wg_v93 = eval.m31_sub(offset0_col3, m31_32768);
    let wg_v94 = eval.m31_sub(offset1_col4, m31_32768);
    let wg_v95 = eval.m31_sub(offset2_col5, m31_32768);
    let decode_instruction_7785f_output_tmp_d5af5_11 = (
        [wg_v93, wg_v94, wg_v95],
        [
            dst_base_fp_col6,
            op0_base_fp_col7,
            op1_imm_col8,
            op1_base_fp_col9,
            op1_base_ap_tmp_d5af5_9,
            m31_1,
            m31_0,
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
        decode_instruction_7785f_output_tmp_d5af5_11.1[4],
        input_ap_col1,
    );
    let mem1_base_col13 = eval.m31_add(wg_v104, wg_v105);
    eval.set_col(13, mem1_base_col13);
    let wg_v106 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_d5af5_11.0[0],
    );
    let memory_address_to_id_value_tmp_d5af5_12 = eval.mem_addr_to_id(wg_v106);
    let dst_id_col14 = memory_address_to_id_value_tmp_d5af5_12;
    eval.set_col(14, dst_id_col14);
    let wg_v107 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_d5af5_11.0[0],
    );
    eval.set_sub_input_word(7, wg_v107);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v108 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_d5af5_11.0[0],
    );
    eval.set_lookup_word(9, wg_v108);
    eval.set_lookup_word(10, dst_id_col14);
    let memory_id_to_big_value_tmp_d5af5_14 = eval.mem_id_to_value(dst_id_col14);
    let dst_limb_0_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 0);
    eval.set_col(15, dst_limb_0_col15);
    let dst_limb_1_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 1);
    eval.set_col(16, dst_limb_1_col16);
    let dst_limb_2_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 2);
    eval.set_col(17, dst_limb_2_col17);
    let dst_limb_3_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 3);
    eval.set_col(18, dst_limb_3_col18);
    let dst_limb_4_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 4);
    eval.set_col(19, dst_limb_4_col19);
    let dst_limb_5_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 5);
    eval.set_col(20, dst_limb_5_col20);
    let dst_limb_6_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 6);
    eval.set_col(21, dst_limb_6_col21);
    let dst_limb_7_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 7);
    eval.set_col(22, dst_limb_7_col22);
    let dst_limb_8_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 8);
    eval.set_col(23, dst_limb_8_col23);
    let dst_limb_9_col24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 9);
    eval.set_col(24, dst_limb_9_col24);
    let dst_limb_10_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 10);
    eval.set_col(25, dst_limb_10_col25);
    let dst_limb_11_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 11);
    eval.set_col(26, dst_limb_11_col26);
    let dst_limb_12_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 12);
    eval.set_col(27, dst_limb_12_col27);
    let dst_limb_13_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 13);
    eval.set_col(28, dst_limb_13_col28);
    let dst_limb_14_col29 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 14);
    eval.set_col(29, dst_limb_14_col29);
    let dst_limb_15_col30 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 15);
    eval.set_col(30, dst_limb_15_col30);
    let dst_limb_16_col31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 16);
    eval.set_col(31, dst_limb_16_col31);
    let dst_limb_17_col32 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 17);
    eval.set_col(32, dst_limb_17_col32);
    let dst_limb_18_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 18);
    eval.set_col(33, dst_limb_18_col33);
    let dst_limb_19_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 19);
    eval.set_col(34, dst_limb_19_col34);
    let dst_limb_20_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 20);
    eval.set_col(35, dst_limb_20_col35);
    let dst_limb_21_col36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 21);
    eval.set_col(36, dst_limb_21_col36);
    let dst_limb_22_col37 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 22);
    eval.set_col(37, dst_limb_22_col37);
    let dst_limb_23_col38 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 23);
    eval.set_col(38, dst_limb_23_col38);
    let dst_limb_24_col39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 24);
    eval.set_col(39, dst_limb_24_col39);
    let dst_limb_25_col40 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 25);
    eval.set_col(40, dst_limb_25_col40);
    let dst_limb_26_col41 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 26);
    eval.set_col(41, dst_limb_26_col41);
    let dst_limb_27_col42 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_14.clone(), 27);
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
    let read_positive_known_id_num_bits_252_output_tmp_d5af5_15 = eval.felt_from_limbs([
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
    let read_positive_num_bits_252_output_tmp_d5af5_16 = (
        read_positive_known_id_num_bits_252_output_tmp_d5af5_15.clone(),
        dst_id_col14,
    );
    let wg_v109 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_d5af5_11.0[1],
    );
    let memory_address_to_id_value_tmp_d5af5_17 = eval.mem_addr_to_id(wg_v109);
    let op0_id_col43 = memory_address_to_id_value_tmp_d5af5_17;
    eval.set_col(43, op0_id_col43);
    let wg_v110 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_d5af5_11.0[1],
    );
    eval.set_sub_input_word(8, wg_v110);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v111 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_d5af5_11.0[1],
    );
    eval.set_lookup_word(42, wg_v111);
    eval.set_lookup_word(43, op0_id_col43);
    let memory_id_to_big_value_tmp_d5af5_19 = eval.mem_id_to_value(op0_id_col43);
    let op0_limb_0_col44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 0);
    eval.set_col(44, op0_limb_0_col44);
    let op0_limb_1_col45 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 1);
    eval.set_col(45, op0_limb_1_col45);
    let op0_limb_2_col46 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 2);
    eval.set_col(46, op0_limb_2_col46);
    let op0_limb_3_col47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 3);
    eval.set_col(47, op0_limb_3_col47);
    let op0_limb_4_col48 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 4);
    eval.set_col(48, op0_limb_4_col48);
    let op0_limb_5_col49 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 5);
    eval.set_col(49, op0_limb_5_col49);
    let op0_limb_6_col50 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 6);
    eval.set_col(50, op0_limb_6_col50);
    let op0_limb_7_col51 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 7);
    eval.set_col(51, op0_limb_7_col51);
    let op0_limb_8_col52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 8);
    eval.set_col(52, op0_limb_8_col52);
    let op0_limb_9_col53 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 9);
    eval.set_col(53, op0_limb_9_col53);
    let op0_limb_10_col54 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 10);
    eval.set_col(54, op0_limb_10_col54);
    let op0_limb_11_col55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 11);
    eval.set_col(55, op0_limb_11_col55);
    let op0_limb_12_col56 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 12);
    eval.set_col(56, op0_limb_12_col56);
    let op0_limb_13_col57 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 13);
    eval.set_col(57, op0_limb_13_col57);
    let op0_limb_14_col58 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 14);
    eval.set_col(58, op0_limb_14_col58);
    let op0_limb_15_col59 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 15);
    eval.set_col(59, op0_limb_15_col59);
    let op0_limb_16_col60 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 16);
    eval.set_col(60, op0_limb_16_col60);
    let op0_limb_17_col61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 17);
    eval.set_col(61, op0_limb_17_col61);
    let op0_limb_18_col62 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 18);
    eval.set_col(62, op0_limb_18_col62);
    let op0_limb_19_col63 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 19);
    eval.set_col(63, op0_limb_19_col63);
    let op0_limb_20_col64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 20);
    eval.set_col(64, op0_limb_20_col64);
    let op0_limb_21_col65 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 21);
    eval.set_col(65, op0_limb_21_col65);
    let op0_limb_22_col66 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 22);
    eval.set_col(66, op0_limb_22_col66);
    let op0_limb_23_col67 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 23);
    eval.set_col(67, op0_limb_23_col67);
    let op0_limb_24_col68 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 24);
    eval.set_col(68, op0_limb_24_col68);
    let op0_limb_25_col69 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 25);
    eval.set_col(69, op0_limb_25_col69);
    let op0_limb_26_col70 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 26);
    eval.set_col(70, op0_limb_26_col70);
    let op0_limb_27_col71 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_19.clone(), 27);
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
    let read_positive_known_id_num_bits_252_output_tmp_d5af5_20 = eval.felt_from_limbs([
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
    let read_positive_num_bits_252_output_tmp_d5af5_21 = (
        read_positive_known_id_num_bits_252_output_tmp_d5af5_20.clone(),
        op0_id_col43,
    );
    let wg_v112 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_d5af5_11.0[2],
    );
    let memory_address_to_id_value_tmp_d5af5_22 = eval.mem_addr_to_id(wg_v112);
    let op1_id_col72 = memory_address_to_id_value_tmp_d5af5_22;
    eval.set_col(72, op1_id_col72);
    let wg_v113 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_d5af5_11.0[2],
    );
    eval.set_sub_input_word(9, wg_v113);
    eval.set_lookup_word(74, m31_1444891767);
    let wg_v114 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_d5af5_11.0[2],
    );
    eval.set_lookup_word(75, wg_v114);
    eval.set_lookup_word(76, op1_id_col72);
    let memory_id_to_big_value_tmp_d5af5_24 = eval.mem_id_to_value(op1_id_col72);
    let op1_limb_0_col73 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 0);
    eval.set_col(73, op1_limb_0_col73);
    let op1_limb_1_col74 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 1);
    eval.set_col(74, op1_limb_1_col74);
    let op1_limb_2_col75 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 2);
    eval.set_col(75, op1_limb_2_col75);
    let op1_limb_3_col76 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 3);
    eval.set_col(76, op1_limb_3_col76);
    let op1_limb_4_col77 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 4);
    eval.set_col(77, op1_limb_4_col77);
    let op1_limb_5_col78 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 5);
    eval.set_col(78, op1_limb_5_col78);
    let op1_limb_6_col79 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 6);
    eval.set_col(79, op1_limb_6_col79);
    let op1_limb_7_col80 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 7);
    eval.set_col(80, op1_limb_7_col80);
    let op1_limb_8_col81 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 8);
    eval.set_col(81, op1_limb_8_col81);
    let op1_limb_9_col82 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 9);
    eval.set_col(82, op1_limb_9_col82);
    let op1_limb_10_col83 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 10);
    eval.set_col(83, op1_limb_10_col83);
    let op1_limb_11_col84 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 11);
    eval.set_col(84, op1_limb_11_col84);
    let op1_limb_12_col85 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 12);
    eval.set_col(85, op1_limb_12_col85);
    let op1_limb_13_col86 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 13);
    eval.set_col(86, op1_limb_13_col86);
    let op1_limb_14_col87 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 14);
    eval.set_col(87, op1_limb_14_col87);
    let op1_limb_15_col88 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 15);
    eval.set_col(88, op1_limb_15_col88);
    let op1_limb_16_col89 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 16);
    eval.set_col(89, op1_limb_16_col89);
    let op1_limb_17_col90 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 17);
    eval.set_col(90, op1_limb_17_col90);
    let op1_limb_18_col91 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 18);
    eval.set_col(91, op1_limb_18_col91);
    let op1_limb_19_col92 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 19);
    eval.set_col(92, op1_limb_19_col92);
    let op1_limb_20_col93 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 20);
    eval.set_col(93, op1_limb_20_col93);
    let op1_limb_21_col94 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 21);
    eval.set_col(94, op1_limb_21_col94);
    let op1_limb_22_col95 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 22);
    eval.set_col(95, op1_limb_22_col95);
    let op1_limb_23_col96 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 23);
    eval.set_col(96, op1_limb_23_col96);
    let op1_limb_24_col97 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 24);
    eval.set_col(97, op1_limb_24_col97);
    let op1_limb_25_col98 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 25);
    eval.set_col(98, op1_limb_25_col98);
    let op1_limb_26_col99 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 26);
    eval.set_col(99, op1_limb_26_col99);
    let op1_limb_27_col100 = eval.felt_get_m31(&memory_id_to_big_value_tmp_d5af5_24.clone(), 27);
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
    let read_positive_known_id_num_bits_252_output_tmp_d5af5_25 = eval.felt_from_limbs([
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
    let read_positive_num_bits_252_output_tmp_d5af5_26 = (
        read_positive_known_id_num_bits_252_output_tmp_d5af5_25.clone(),
        op1_id_col72,
    );
    let wg_v115 = eval.u16_from_m31(op0_limb_0_col44);
    let wg_v116 = eval.u16_from_m31(op1_limb_0_col73);
    let wg_v117 = eval.u16_xor(wg_v115, wg_v116);
    let wg_v118 = eval.u16_from_m31(dst_limb_0_col15);
    let wg_v119 = eval.u16_xor(wg_v117, wg_v118);
    let sub_p_bit_tmp_d5af5_27 = eval.u16_and(wg_v119, 1);
    let sub_p_bit_col101 = eval.u16_as_m31(sub_p_bit_tmp_d5af5_27);
    eval.set_col(101, sub_p_bit_col101);
    let enabler_col102 = eval.enabler();
    eval.set_col(102, enabler_col102);
    eval.set_lookup_word(107, m31_428564188);
    eval.set_lookup_word(108, input_pc_col0);
    eval.set_lookup_word(109, input_ap_col1);
    eval.set_lookup_word(110, input_fp_col2);
    eval.set_lookup_word(111, m31_428564188);
    let wg_v120 = eval.m31_add(input_pc_col0, m31_1);
    let wg_v121 = eval.m31_add(wg_v120, op1_imm_col8);
    eval.set_lookup_word(112, wg_v121);
    let wg_v122 = eval.m31_add(input_ap_col1, ap_update_add_1_col10);
    eval.set_lookup_word(113, wg_v122);
    eval.set_lookup_word(114, input_fp_col2);
    eval.set_lookup_word(115, m31_1);
    eval.set_lookup_word(116, enabler_col102);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `add_opcode_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
            |(row_index, (row, lookup_data, sub_component_inputs, add_opcode_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    add_opcode_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                add_opcode_row_body(&mut eval);
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
                *lookup_data.opcodes_7 = [lw[107], lw[108], lw[109], lw[110]];
                *lookup_data.opcodes_8 = [lw[111], lw[112], lw[113], lw[114]];
                *lookup_data.mults_0 = lw[115];
                *lookup_data.mults_1 = lw[116];
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

/// Record the `add_opcode` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_add_opcode() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("add_opcode");
    add_opcode_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    117;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    memory_address_to_id_5: 3,
    memory_id_to_big_6: 30,
    opcodes_7: 4,
    opcodes_8: 4,
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
        "opcodes_7",
        "mults_1",
        false,
    ),
    ("opcodes_8", "mults_1", true, "", "", false),
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
        ld.opcodes_7.iter().flatten().copied().collect(),
        ld.opcodes_8.iter().flatten().copied().collect(),
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
    memory_address_to_id_5: Vec<[PackedM31; 3]>,
    memory_id_to_big_6: Vec<[PackedM31; 30]>,
    opcodes_7: Vec<[PackedM31; 4]>,
    opcodes_8: Vec<[PackedM31; 4]>,
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
    opcodes_7: 4,
    opcodes_8: 4,
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
            &self.lookup_data.opcodes_7,
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
            &self.lookup_data.opcodes_8,
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

// --- jit_prove additive accessors (hand-written, NOT transformer-emitted; kept
// here because `LookupData`/`InteractionClaimGenerator` are module-private). The
// flat-word layouts mirror the emitted `set_lookup_word`/`set_sub_input_word`
// indices exactly (declaration order); both are regression-fenced by
// `jit_prove_backend::tests`. ---

/// PROVE-LANE SHADOW DIFF (debug instrument, `STWO_JIT_PROVE_SHADOW=1`): run the
/// host SIMD writer — a PURE read of the states, no feeding — beside the device
/// lane's outputs and report the first divergences per surface (committed trace,
/// lookup words, sub words) with exact (row, column/word) coordinates. Observation
/// only; the caller's lane proceeds unchanged.
pub(crate) fn shadow_compare_against_host(
    inputs: &[InputType],
    device_cols: &[Vec<u32>],
    lookup_flat: &[u32],
    sub_flat: &[u32],
    n_padded: usize,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_instruction_state: &verify_instruction::ClaimGenerator,
) {
    use stwo::prover::backend::simd::m31::N_LANES;
    let n_rows = inputs.len();
    let mut padded = inputs.to_vec();
    padded.resize(n_padded, *padded.first().unwrap());
    let packed = pack_values(&padded);
    let (trace, ld, sci) = write_trace_simd(
        packed,
        n_rows,
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
    );
    let n_packed_rows = n_padded / N_LANES;
    let mut bad = 0usize;
    for r in 0..n_padded {
        let host_row = trace.row_at(r);
        for c in 0..N_TRACE_COLUMNS {
            if device_cols[c][r] != host_row[c].0 {
                eprintln!(
                    "SHADOW trace row {r} col {c}: host {} device {} (real={})",
                    host_row[c].0,
                    device_cols[c][r],
                    r < n_rows
                );
                bad += 1;
                if bad >= 8 {
                    return;
                }
            }
        }
    }
    let mut check_flats = |name: &str, flats: Vec<Vec<PackedM31>>, dev: &[u32]| {
        let mut w = 0usize;
        for (fi, field) in flats.iter().enumerate() {
            let width = field.len() / n_packed_rows;
            for k in 0..width {
                for r in 0..n_padded {
                    let hv = field[(r / N_LANES) * width + k].to_array()[r % N_LANES].0;
                    let dv = dev[w * n_padded + r];
                    if hv != dv {
                        eprintln!(
                            "SHADOW {name} row {r} word {w} (field {fi}+{k}): host {hv} \
                             device {dv} (real={})",
                            r < n_rows
                        );
                        bad += 1;
                        if bad >= 16 {
                            return;
                        }
                    }
                }
                w += 1;
            }
        }
    };
    check_flats("lookup", lookup_data_flat(&ld), lookup_flat);
    let mut check_raw = |name: &str, flats: Vec<Vec<Simd<u32, N_LANES>>>, dev: &[u32]| {
        let mut w = 0usize;
        for (fi, field) in flats.iter().enumerate() {
            let width = field.len() / n_packed_rows;
            for k in 0..width {
                for r in 0..n_padded {
                    let hv = field[(r / N_LANES) * width + k].as_array()[r % N_LANES];
                    let dv = dev[w * n_padded + r];
                    if hv != dv {
                        eprintln!(
                            "SHADOW {name} row {r} word {w} (field {fi}+{k}): host {hv} \
                             device {dv} (real={})",
                            r < n_rows
                        );
                        bad += 1;
                        if bad >= 16 {
                            return;
                        }
                    }
                }
                w += 1;
            }
        }
    };
    check_raw("sub", sub_inputs_flat(&sci), sub_flat);
    eprintln!(
        "SHADOW add_opcode: {} divergences ({} padded rows, {} real)",
        bad, n_padded, n_rows
    );
}

/// The sub-component inputs decoded from the device kernel's flat sub-input words
/// (word-major, N_SUB_INPUT_WORDS per row). Word order mirrors the emitted
/// `set_sub_input_word` indices: 0..=6 the verify_instruction tuple, 7..=9 the three
/// memory addresses, 10..=12 the three ids.
pub(crate) struct SubInputsFromFlat {
    pub verify_instruction: Vec<verify_instruction::InputType>,
    pub memory_address_to_id: [Vec<memory_address_to_id::InputType>; 3],
    pub memory_id_to_big: [Vec<memory_id_to_big::InputType>; 3],
}

/// Decode the flat sub-input words for ALL `n_rows` rows — padding rows included.
/// The host writer feeds the full padded vectors (`add_inputs` over
/// `inputs.len() * N_LANES`): every row emits its sub-relation uses with
/// multiplicity `mults_0 = 1` regardless of the enabler, so the downstream states
/// must receive the padding rows' (first-input-replicated) feeds too or the logup
/// sums don't balance. Truncating at the real row count here is an
/// invalid-proof bug, not an optimization.
pub(crate) fn sub_inputs_from_flat(words: &[u32], n_rows: usize) -> SubInputsFromFlat {
    assert_eq!(words.len(), N_SUB_INPUT_WORDS * n_rows);
    let w = |word: usize, r: usize| M31::from_u32_unchecked(words[word * n_rows + r]);
    let decode_scalar = |word: usize| -> Vec<M31> { (0..n_rows).map(|r| w(word, r)).collect() };
    SubInputsFromFlat {
        verify_instruction: (0..n_rows)
            .map(|r| {
                (
                    w(0, r),
                    [w(1, r), w(2, r), w(3, r)],
                    [w(4, r), w(5, r)],
                    w(6, r),
                )
            })
            .collect(),
        memory_address_to_id: [decode_scalar(7), decode_scalar(8), decode_scalar(9)],
        memory_id_to_big: [decode_scalar(10), decode_scalar(11), decode_scalar(12)],
    }
}

/// Feed the decoded sub-inputs into the downstream states — the same entry points,
/// per-relation order, and full padded extent as the host writer's `add_inputs` loops.
pub(crate) fn feed_sub_inputs_from_flat(
    words: &[u32],
    n_rows: usize,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_instruction_state: &verify_instruction::ClaimGenerator,
    device_fed: &[&'static str],
) {
    let sub = sub_inputs_from_flat(words, n_rows);
    for input in &sub.verify_instruction {
        AddInputs::add_input(verify_instruction_state, input, 0);
    }
    if !device_fed.contains(&"memory_address_to_id_state") {
        for addrs in &sub.memory_address_to_id {
            memory_address_to_id_state.add_inputs(addrs);
        }
    }
    if !device_fed.contains(&"memory_id_to_big_state") {
        for ids in &sub.memory_id_to_big {
            memory_id_to_big_state.add_inputs(ids);
        }
    }
}
