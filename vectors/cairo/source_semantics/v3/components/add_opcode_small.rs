// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::add_opcode_small::{Claim, InteractionClaim, N_TRACE_COLUMNS};
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
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_508 = PackedM31::broadcast(M31::from(508));
    let M31_511 = PackedM31::broadcast(M31::from(511));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_536870912 = PackedM31::broadcast(M31::from(536870912));
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
            |(row_index, (row, lookup_data, sub_component_inputs, add_opcode_small_input))| {
                let input_pc_col0 = add_opcode_small_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = add_opcode_small_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = add_opcode_small_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_e5099_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_e5099_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_e5099_0);
                let offset0_tmp_e5099_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_e5099_2.as_m31();
                *row[3] = offset0_col3;
                let offset1_tmp_e5099_3 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(1)))
                        >> (UInt16_7))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(2),
                        )) << (UInt16_2)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(3),
                        )) & (UInt16_31))
                            << (UInt16_11)));
                let offset1_col4 = offset1_tmp_e5099_3.as_m31();
                *row[4] = offset1_col4;
                let offset2_tmp_e5099_4 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(3)))
                        >> (UInt16_5))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(4),
                        )) << (UInt16_4)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(5),
                        )) & (UInt16_7))
                            << (UInt16_13)));
                let offset2_col5 = offset2_tmp_e5099_4.as_m31();
                *row[5] = offset2_col5;
                let dst_base_fp_tmp_e5099_5 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col6 = dst_base_fp_tmp_e5099_5.as_m31();
                *row[6] = dst_base_fp_col6;
                let op0_base_fp_tmp_e5099_6 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_1))
                        & (UInt16_1));
                let op0_base_fp_col7 = op0_base_fp_tmp_e5099_6.as_m31();
                *row[7] = op0_base_fp_col7;
                let op1_imm_tmp_e5099_7 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_2))
                        & (UInt16_1));
                let op1_imm_col8 = op1_imm_tmp_e5099_7.as_m31();
                *row[8] = op1_imm_col8;
                let op1_base_fp_tmp_e5099_8 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_3))
                        & (UInt16_1));
                let op1_base_fp_col9 = op1_base_fp_tmp_e5099_8.as_m31();
                *row[9] = op1_base_fp_col9;
                let op1_base_ap_tmp_e5099_9 = (((M31_1) - (op1_imm_col8)) - (op1_base_fp_col9));
                let ap_update_add_1_tmp_e5099_10 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_e5099_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col10 = ap_update_add_1_tmp_e5099_10.as_m31();
                *row[10] = ap_update_add_1_col10;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, offset1_col4, offset2_col5],
                    [
                        (((((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                            + ((op1_imm_col8) * (M31_32)))
                            + ((op1_base_fp_col9) * (M31_64)))
                            + ((op1_base_ap_tmp_e5099_9) * (M31_128)))
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
                        + ((op1_base_ap_tmp_e5099_9) * (M31_128)))
                        + (M31_256)),
                    (((ap_update_add_1_col10) * (M31_32)) + (M31_256)),
                    M31_0,
                ];
                let decode_instruction_7785f_output_tmp_e5099_11 = (
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
                        op1_base_ap_tmp_e5099_9,
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
                    + ((decode_instruction_7785f_output_tmp_e5099_11.1[4]) * (input_ap_col1)));
                *row[13] = mem1_base_col13;

                // Read Small.

                // Read Id.

                let memory_address_to_id_value_tmp_e5099_12 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col11)
                            + (decode_instruction_7785f_output_tmp_e5099_11.0[0])),
                    );
                let dst_id_col14 = memory_address_to_id_value_tmp_e5099_12;
                *row[14] = dst_id_col14;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem_dst_base_col11) + (decode_instruction_7785f_output_tmp_e5099_11.0[0]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem_dst_base_col11) + (decode_instruction_7785f_output_tmp_e5099_11.0[0])),
                    dst_id_col14,
                ];

                let memory_id_to_big_value_tmp_e5099_14 =
                    memory_id_to_big_state.deduce_output(dst_id_col14);

                // Decode Small Sign.

                let msb_tmp_e5099_15 = memory_id_to_big_value_tmp_e5099_14.get_m31(27).eq(M31_256);
                let msb_col15 = msb_tmp_e5099_15.as_m31();
                *row[15] = msb_col15;
                let mid_limbs_set_tmp_e5099_16 =
                    ((memory_id_to_big_value_tmp_e5099_14.get_m31(20).eq(M31_511))
                        & (msb_tmp_e5099_15));
                let mid_limbs_set_col16 = mid_limbs_set_tmp_e5099_16.as_m31();
                *row[16] = mid_limbs_set_col16;
                let decode_small_sign_output_tmp_e5099_17 = [
                    msb_col15,
                    mid_limbs_set_col16,
                    ((mid_limbs_set_col16) * (M31_508)),
                    ((mid_limbs_set_col16) * (M31_511)),
                    (((msb_col15) * (M31_136)) - (mid_limbs_set_col16)),
                    ((msb_col15) * (M31_256)),
                ];

                let dst_limb_0_col17 = memory_id_to_big_value_tmp_e5099_14.get_m31(0);
                *row[17] = dst_limb_0_col17;
                let dst_limb_1_col18 = memory_id_to_big_value_tmp_e5099_14.get_m31(1);
                *row[18] = dst_limb_1_col18;
                let dst_limb_2_col19 = memory_id_to_big_value_tmp_e5099_14.get_m31(2);
                *row[19] = dst_limb_2_col19;
                let remainder_bits_tmp_e5099_18 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_14.get_m31(3)))
                        & (UInt16_3));
                let remainder_bits_col20 = remainder_bits_tmp_e5099_18.as_m31();
                *row[20] = remainder_bits_col20;

                // Cond Range Check 2.

                let partial_limb_msb_tmp_e5099_19 =
                    (((PackedUInt16::from_m31(remainder_bits_col20)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col21 = partial_limb_msb_tmp_e5099_19.as_m31();
                *row[21] = partial_limb_msb_col21;

                *sub_component_inputs.memory_id_to_big[0] = dst_id_col14;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    dst_id_col14,
                    dst_limb_0_col17,
                    dst_limb_1_col18,
                    dst_limb_2_col19,
                    ((remainder_bits_col20) + (decode_small_sign_output_tmp_e5099_17[2])),
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[3],
                    decode_small_sign_output_tmp_e5099_17[4],
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    decode_small_sign_output_tmp_e5099_17[5],
                ];
                let read_small_output_tmp_e5099_21 = (
                    ((((((dst_limb_0_col17) + ((dst_limb_1_col18) * (M31_512)))
                        + ((dst_limb_2_col19) * (M31_262144)))
                        + ((remainder_bits_col20) * (M31_134217728)))
                        - (msb_col15))
                        - ((M31_536870912) * (mid_limbs_set_col16))),
                    dst_id_col14,
                );

                // Read Small.

                // Read Id.

                let memory_address_to_id_value_tmp_e5099_22 = memory_address_to_id_state
                    .deduce_output(
                        ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_e5099_11.0[1])),
                    );
                let op0_id_col22 = memory_address_to_id_value_tmp_e5099_22;
                *row[22] = op0_id_col22;
                *sub_component_inputs.memory_address_to_id[1] =
                    ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_e5099_11.0[1]));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((mem0_base_col12) + (decode_instruction_7785f_output_tmp_e5099_11.0[1])),
                    op0_id_col22,
                ];

                let memory_id_to_big_value_tmp_e5099_24 =
                    memory_id_to_big_state.deduce_output(op0_id_col22);

                // Decode Small Sign.

                let msb_tmp_e5099_25 = memory_id_to_big_value_tmp_e5099_24.get_m31(27).eq(M31_256);
                let msb_col23 = msb_tmp_e5099_25.as_m31();
                *row[23] = msb_col23;
                let mid_limbs_set_tmp_e5099_26 =
                    ((memory_id_to_big_value_tmp_e5099_24.get_m31(20).eq(M31_511))
                        & (msb_tmp_e5099_25));
                let mid_limbs_set_col24 = mid_limbs_set_tmp_e5099_26.as_m31();
                *row[24] = mid_limbs_set_col24;
                let decode_small_sign_output_tmp_e5099_27 = [
                    msb_col23,
                    mid_limbs_set_col24,
                    ((mid_limbs_set_col24) * (M31_508)),
                    ((mid_limbs_set_col24) * (M31_511)),
                    (((msb_col23) * (M31_136)) - (mid_limbs_set_col24)),
                    ((msb_col23) * (M31_256)),
                ];

                let op0_limb_0_col25 = memory_id_to_big_value_tmp_e5099_24.get_m31(0);
                *row[25] = op0_limb_0_col25;
                let op0_limb_1_col26 = memory_id_to_big_value_tmp_e5099_24.get_m31(1);
                *row[26] = op0_limb_1_col26;
                let op0_limb_2_col27 = memory_id_to_big_value_tmp_e5099_24.get_m31(2);
                *row[27] = op0_limb_2_col27;
                let remainder_bits_tmp_e5099_28 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_24.get_m31(3)))
                        & (UInt16_3));
                let remainder_bits_col28 = remainder_bits_tmp_e5099_28.as_m31();
                *row[28] = remainder_bits_col28;

                // Cond Range Check 2.

                let partial_limb_msb_tmp_e5099_29 =
                    (((PackedUInt16::from_m31(remainder_bits_col28)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col29 = partial_limb_msb_tmp_e5099_29.as_m31();
                *row[29] = partial_limb_msb_col29;

                *sub_component_inputs.memory_id_to_big[1] = op0_id_col22;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    op0_id_col22,
                    op0_limb_0_col25,
                    op0_limb_1_col26,
                    op0_limb_2_col27,
                    ((remainder_bits_col28) + (decode_small_sign_output_tmp_e5099_27[2])),
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[3],
                    decode_small_sign_output_tmp_e5099_27[4],
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    decode_small_sign_output_tmp_e5099_27[5],
                ];
                let read_small_output_tmp_e5099_31 = (
                    ((((((op0_limb_0_col25) + ((op0_limb_1_col26) * (M31_512)))
                        + ((op0_limb_2_col27) * (M31_262144)))
                        + ((remainder_bits_col28) * (M31_134217728)))
                        - (msb_col23))
                        - ((M31_536870912) * (mid_limbs_set_col24))),
                    op0_id_col22,
                );

                // Read Small.

                // Read Id.

                let memory_address_to_id_value_tmp_e5099_32 = memory_address_to_id_state
                    .deduce_output(
                        ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_e5099_11.0[2])),
                    );
                let op1_id_col30 = memory_address_to_id_value_tmp_e5099_32;
                *row[30] = op1_id_col30;
                *sub_component_inputs.memory_address_to_id[2] =
                    ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_e5099_11.0[2]));
                *lookup_data.memory_address_to_id_5 = [
                    M31_1444891767,
                    ((mem1_base_col13) + (decode_instruction_7785f_output_tmp_e5099_11.0[2])),
                    op1_id_col30,
                ];

                let memory_id_to_big_value_tmp_e5099_34 =
                    memory_id_to_big_state.deduce_output(op1_id_col30);

                // Decode Small Sign.

                let msb_tmp_e5099_35 = memory_id_to_big_value_tmp_e5099_34.get_m31(27).eq(M31_256);
                let msb_col31 = msb_tmp_e5099_35.as_m31();
                *row[31] = msb_col31;
                let mid_limbs_set_tmp_e5099_36 =
                    ((memory_id_to_big_value_tmp_e5099_34.get_m31(20).eq(M31_511))
                        & (msb_tmp_e5099_35));
                let mid_limbs_set_col32 = mid_limbs_set_tmp_e5099_36.as_m31();
                *row[32] = mid_limbs_set_col32;
                let decode_small_sign_output_tmp_e5099_37 = [
                    msb_col31,
                    mid_limbs_set_col32,
                    ((mid_limbs_set_col32) * (M31_508)),
                    ((mid_limbs_set_col32) * (M31_511)),
                    (((msb_col31) * (M31_136)) - (mid_limbs_set_col32)),
                    ((msb_col31) * (M31_256)),
                ];

                let op1_limb_0_col33 = memory_id_to_big_value_tmp_e5099_34.get_m31(0);
                *row[33] = op1_limb_0_col33;
                let op1_limb_1_col34 = memory_id_to_big_value_tmp_e5099_34.get_m31(1);
                *row[34] = op1_limb_1_col34;
                let op1_limb_2_col35 = memory_id_to_big_value_tmp_e5099_34.get_m31(2);
                *row[35] = op1_limb_2_col35;
                let remainder_bits_tmp_e5099_38 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_e5099_34.get_m31(3)))
                        & (UInt16_3));
                let remainder_bits_col36 = remainder_bits_tmp_e5099_38.as_m31();
                *row[36] = remainder_bits_col36;

                // Cond Range Check 2.

                let partial_limb_msb_tmp_e5099_39 =
                    (((PackedUInt16::from_m31(remainder_bits_col36)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col37 = partial_limb_msb_tmp_e5099_39.as_m31();
                *row[37] = partial_limb_msb_col37;

                *sub_component_inputs.memory_id_to_big[2] = op1_id_col30;
                *lookup_data.memory_id_to_big_6 = [
                    M31_1662111297,
                    op1_id_col30,
                    op1_limb_0_col33,
                    op1_limb_1_col34,
                    op1_limb_2_col35,
                    ((remainder_bits_col36) + (decode_small_sign_output_tmp_e5099_37[2])),
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[3],
                    decode_small_sign_output_tmp_e5099_37[4],
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    decode_small_sign_output_tmp_e5099_37[5],
                ];
                let read_small_output_tmp_e5099_41 = (
                    ((((((op1_limb_0_col33) + ((op1_limb_1_col34) * (M31_512)))
                        + ((op1_limb_2_col35) * (M31_262144)))
                        + ((remainder_bits_col36) * (M31_134217728)))
                        - (msb_col31))
                        - ((M31_536870912) * (mid_limbs_set_col32))),
                    op1_id_col30,
                );

                let enabler_col38 = enabler_col.packed_at(row_index);
                *row[38] = enabler_col38;
                *lookup_data.opcodes_7 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_8 = [
                    M31_428564188,
                    (((input_pc_col0) + (M31_1)) + (op1_imm_col8)),
                    ((input_ap_col1) + (ap_update_add_1_col10)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col38;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `add_opcode_small` — mechanical rewrite of
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

/// The per-row `add_opcode_small` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn add_opcode_small_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_8 = eval.m31_const(8);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_128 = eval.m31_const(128);
    let m31_136 = eval.m31_const(136);
    let m31_256 = eval.m31_const(256);
    let m31_508 = eval.m31_const(508);
    let m31_511 = eval.m31_const(511);
    let m31_512 = eval.m31_const(512);
    let m31_32768 = eval.m31_const(32768);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_536870912 = eval.m31_const(536870912);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_e5099_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_e5099_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_e5099_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_e5099_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_e5099_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 1);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 7);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 2);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 2);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 3);
    let wg_v14 = eval.u16_from_m31(wg_v13);
    let wg_v15 = eval.u16_and(wg_v14, 31);
    let wg_v16 = eval.u16_shl(wg_v15, 11);
    let offset1_tmp_e5099_3 = eval.u16_add(wg_v12, wg_v16);
    let offset1_col4 = eval.u16_as_m31(offset1_tmp_e5099_3);
    eval.set_col(4, offset1_col4);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 3);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shr(wg_v18, 5);
    let wg_v20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 4);
    let wg_v21 = eval.u16_from_m31(wg_v20);
    let wg_v22 = eval.u16_shl(wg_v21, 4);
    let wg_v23 = eval.u16_add(wg_v19, wg_v22);
    let wg_v24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v25 = eval.u16_from_m31(wg_v24);
    let wg_v26 = eval.u16_and(wg_v25, 7);
    let wg_v27 = eval.u16_shl(wg_v26, 13);
    let offset2_tmp_e5099_4 = eval.u16_add(wg_v23, wg_v27);
    let offset2_col5 = eval.u16_as_m31(offset2_tmp_e5099_4);
    eval.set_col(5, offset2_col5);
    let wg_v28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v29 = eval.u16_from_m31(wg_v28);
    let wg_v30 = eval.u16_shr(wg_v29, 3);
    let wg_v31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 6);
    let wg_v32 = eval.u16_from_m31(wg_v31);
    let wg_v33 = eval.u16_shl(wg_v32, 6);
    let wg_v34 = eval.u16_add(wg_v30, wg_v33);
    let wg_v35 = eval.u16_shr(wg_v34, 0);
    let dst_base_fp_tmp_e5099_5 = eval.u16_and(wg_v35, 1);
    let dst_base_fp_col6 = eval.u16_as_m31(dst_base_fp_tmp_e5099_5);
    eval.set_col(6, dst_base_fp_col6);
    let wg_v36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v37 = eval.u16_from_m31(wg_v36);
    let wg_v38 = eval.u16_shr(wg_v37, 3);
    let wg_v39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 6);
    let wg_v40 = eval.u16_from_m31(wg_v39);
    let wg_v41 = eval.u16_shl(wg_v40, 6);
    let wg_v42 = eval.u16_add(wg_v38, wg_v41);
    let wg_v43 = eval.u16_shr(wg_v42, 1);
    let op0_base_fp_tmp_e5099_6 = eval.u16_and(wg_v43, 1);
    let op0_base_fp_col7 = eval.u16_as_m31(op0_base_fp_tmp_e5099_6);
    eval.set_col(7, op0_base_fp_col7);
    let wg_v44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v45 = eval.u16_from_m31(wg_v44);
    let wg_v46 = eval.u16_shr(wg_v45, 3);
    let wg_v47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 6);
    let wg_v48 = eval.u16_from_m31(wg_v47);
    let wg_v49 = eval.u16_shl(wg_v48, 6);
    let wg_v50 = eval.u16_add(wg_v46, wg_v49);
    let wg_v51 = eval.u16_shr(wg_v50, 2);
    let op1_imm_tmp_e5099_7 = eval.u16_and(wg_v51, 1);
    let op1_imm_col8 = eval.u16_as_m31(op1_imm_tmp_e5099_7);
    eval.set_col(8, op1_imm_col8);
    let wg_v52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v53 = eval.u16_from_m31(wg_v52);
    let wg_v54 = eval.u16_shr(wg_v53, 3);
    let wg_v55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 6);
    let wg_v56 = eval.u16_from_m31(wg_v55);
    let wg_v57 = eval.u16_shl(wg_v56, 6);
    let wg_v58 = eval.u16_add(wg_v54, wg_v57);
    let wg_v59 = eval.u16_shr(wg_v58, 3);
    let op1_base_fp_tmp_e5099_8 = eval.u16_and(wg_v59, 1);
    let op1_base_fp_col9 = eval.u16_as_m31(op1_base_fp_tmp_e5099_8);
    eval.set_col(9, op1_base_fp_col9);
    let wg_v60 = eval.m31_sub(m31_1, op1_imm_col8);
    let op1_base_ap_tmp_e5099_9 = eval.m31_sub(wg_v60, op1_base_fp_col9);
    let wg_v61 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 5);
    let wg_v62 = eval.u16_from_m31(wg_v61);
    let wg_v63 = eval.u16_shr(wg_v62, 3);
    let wg_v64 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_1.clone(), 6);
    let wg_v65 = eval.u16_from_m31(wg_v64);
    let wg_v66 = eval.u16_shl(wg_v65, 6);
    let wg_v67 = eval.u16_add(wg_v63, wg_v66);
    let wg_v68 = eval.u16_shr(wg_v67, 11);
    let ap_update_add_1_tmp_e5099_10 = eval.u16_and(wg_v68, 1);
    let ap_update_add_1_col10 = eval.u16_as_m31(ap_update_add_1_tmp_e5099_10);
    eval.set_col(10, ap_update_add_1_col10);
    let wg_v69 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v70 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v71 = eval.m31_add(wg_v69, wg_v70);
    let wg_v72 = eval.m31_mul(op1_imm_col8, m31_32);
    let wg_v73 = eval.m31_add(wg_v71, wg_v72);
    let wg_v74 = eval.m31_mul(op1_base_fp_col9, m31_64);
    let wg_v75 = eval.m31_add(wg_v73, wg_v74);
    let wg_v76 = eval.m31_mul(op1_base_ap_tmp_e5099_9, m31_128);
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
    let wg_v88 = eval.m31_mul(op1_base_ap_tmp_e5099_9, m31_128);
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
    let decode_instruction_7785f_output_tmp_e5099_11 = (
        [wg_v93, wg_v94, wg_v95],
        [
            dst_base_fp_col6,
            op0_base_fp_col7,
            op1_imm_col8,
            op1_base_fp_col9,
            op1_base_ap_tmp_e5099_9,
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
        decode_instruction_7785f_output_tmp_e5099_11.1[4],
        input_ap_col1,
    );
    let mem1_base_col13 = eval.m31_add(wg_v104, wg_v105);
    eval.set_col(13, mem1_base_col13);
    let wg_v106 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_e5099_11.0[0],
    );
    let memory_address_to_id_value_tmp_e5099_12 = eval.mem_addr_to_id(wg_v106);
    let dst_id_col14 = memory_address_to_id_value_tmp_e5099_12;
    eval.set_col(14, dst_id_col14);
    let wg_v107 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_e5099_11.0[0],
    );
    eval.set_sub_input_word(7, wg_v107);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v108 = eval.m31_add(
        mem_dst_base_col11,
        decode_instruction_7785f_output_tmp_e5099_11.0[0],
    );
    eval.set_lookup_word(9, wg_v108);
    eval.set_lookup_word(10, dst_id_col14);
    let memory_id_to_big_value_tmp_e5099_14 = eval.mem_id_to_value(dst_id_col14);
    let wg_v109 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 27);
    let msb_tmp_e5099_15 = eval.m31_eq(wg_v109, m31_256);
    let msb_col15 = eval.mask_as_m31(msb_tmp_e5099_15);
    eval.set_col(15, msb_col15);
    let wg_v110 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 20);
    let wg_v111 = eval.m31_eq(wg_v110, m31_511);
    let mid_limbs_set_tmp_e5099_16 = eval.mask_and(wg_v111, msb_tmp_e5099_15);
    let mid_limbs_set_col16 = eval.mask_as_m31(mid_limbs_set_tmp_e5099_16);
    eval.set_col(16, mid_limbs_set_col16);
    let wg_v112 = eval.m31_mul(mid_limbs_set_col16, m31_508);
    let wg_v113 = eval.m31_mul(mid_limbs_set_col16, m31_511);
    let wg_v114 = eval.m31_mul(msb_col15, m31_136);
    let wg_v115 = eval.m31_sub(wg_v114, mid_limbs_set_col16);
    let wg_v116 = eval.m31_mul(msb_col15, m31_256);
    let decode_small_sign_output_tmp_e5099_17 = [
        msb_col15,
        mid_limbs_set_col16,
        wg_v112,
        wg_v113,
        wg_v115,
        wg_v116,
    ];
    let dst_limb_0_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 0);
    eval.set_col(17, dst_limb_0_col17);
    let dst_limb_1_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 1);
    eval.set_col(18, dst_limb_1_col18);
    let dst_limb_2_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 2);
    eval.set_col(19, dst_limb_2_col19);
    let wg_v117 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_14.clone(), 3);
    let wg_v118 = eval.u16_from_m31(wg_v117);
    let remainder_bits_tmp_e5099_18 = eval.u16_and(wg_v118, 3);
    let remainder_bits_col20 = eval.u16_as_m31(remainder_bits_tmp_e5099_18);
    eval.set_col(20, remainder_bits_col20);
    let wg_v119 = eval.u16_from_m31(remainder_bits_col20);
    let wg_v120 = eval.u16_and(wg_v119, 2);
    let partial_limb_msb_tmp_e5099_19 = eval.u16_shr(wg_v120, 1);
    let partial_limb_msb_col21 = eval.u16_as_m31(partial_limb_msb_tmp_e5099_19);
    eval.set_col(21, partial_limb_msb_col21);
    eval.set_sub_input_word(10, dst_id_col14);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, dst_id_col14);
    eval.set_lookup_word(13, dst_limb_0_col17);
    eval.set_lookup_word(14, dst_limb_1_col18);
    eval.set_lookup_word(15, dst_limb_2_col19);
    let wg_v121 = eval.m31_add(
        remainder_bits_col20,
        decode_small_sign_output_tmp_e5099_17[2],
    );
    eval.set_lookup_word(16, wg_v121);
    eval.set_lookup_word(17, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(18, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(19, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(20, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(21, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(22, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(23, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(24, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(25, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(26, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(27, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(28, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(29, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(30, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(31, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(32, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(33, decode_small_sign_output_tmp_e5099_17[3]);
    eval.set_lookup_word(34, decode_small_sign_output_tmp_e5099_17[4]);
    eval.set_lookup_word(35, m31_0);
    eval.set_lookup_word(36, m31_0);
    eval.set_lookup_word(37, m31_0);
    eval.set_lookup_word(38, m31_0);
    eval.set_lookup_word(39, m31_0);
    eval.set_lookup_word(40, decode_small_sign_output_tmp_e5099_17[5]);
    let wg_v122 = eval.m31_mul(dst_limb_1_col18, m31_512);
    let wg_v123 = eval.m31_add(dst_limb_0_col17, wg_v122);
    let wg_v124 = eval.m31_mul(dst_limb_2_col19, m31_262144);
    let wg_v125 = eval.m31_add(wg_v123, wg_v124);
    let wg_v126 = eval.m31_mul(remainder_bits_col20, m31_134217728);
    let wg_v127 = eval.m31_add(wg_v125, wg_v126);
    let wg_v128 = eval.m31_sub(wg_v127, msb_col15);
    let wg_v129 = eval.m31_mul(m31_536870912, mid_limbs_set_col16);
    let wg_v130 = eval.m31_sub(wg_v128, wg_v129);
    let read_small_output_tmp_e5099_21 = (wg_v130, dst_id_col14);
    let wg_v131 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_e5099_11.0[1],
    );
    let memory_address_to_id_value_tmp_e5099_22 = eval.mem_addr_to_id(wg_v131);
    let op0_id_col22 = memory_address_to_id_value_tmp_e5099_22;
    eval.set_col(22, op0_id_col22);
    let wg_v132 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_e5099_11.0[1],
    );
    eval.set_sub_input_word(8, wg_v132);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v133 = eval.m31_add(
        mem0_base_col12,
        decode_instruction_7785f_output_tmp_e5099_11.0[1],
    );
    eval.set_lookup_word(42, wg_v133);
    eval.set_lookup_word(43, op0_id_col22);
    let memory_id_to_big_value_tmp_e5099_24 = eval.mem_id_to_value(op0_id_col22);
    let wg_v134 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 27);
    let msb_tmp_e5099_25 = eval.m31_eq(wg_v134, m31_256);
    let msb_col23 = eval.mask_as_m31(msb_tmp_e5099_25);
    eval.set_col(23, msb_col23);
    let wg_v135 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 20);
    let wg_v136 = eval.m31_eq(wg_v135, m31_511);
    let mid_limbs_set_tmp_e5099_26 = eval.mask_and(wg_v136, msb_tmp_e5099_25);
    let mid_limbs_set_col24 = eval.mask_as_m31(mid_limbs_set_tmp_e5099_26);
    eval.set_col(24, mid_limbs_set_col24);
    let wg_v137 = eval.m31_mul(mid_limbs_set_col24, m31_508);
    let wg_v138 = eval.m31_mul(mid_limbs_set_col24, m31_511);
    let wg_v139 = eval.m31_mul(msb_col23, m31_136);
    let wg_v140 = eval.m31_sub(wg_v139, mid_limbs_set_col24);
    let wg_v141 = eval.m31_mul(msb_col23, m31_256);
    let decode_small_sign_output_tmp_e5099_27 = [
        msb_col23,
        mid_limbs_set_col24,
        wg_v137,
        wg_v138,
        wg_v140,
        wg_v141,
    ];
    let op0_limb_0_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 0);
    eval.set_col(25, op0_limb_0_col25);
    let op0_limb_1_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 1);
    eval.set_col(26, op0_limb_1_col26);
    let op0_limb_2_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 2);
    eval.set_col(27, op0_limb_2_col27);
    let wg_v142 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_24.clone(), 3);
    let wg_v143 = eval.u16_from_m31(wg_v142);
    let remainder_bits_tmp_e5099_28 = eval.u16_and(wg_v143, 3);
    let remainder_bits_col28 = eval.u16_as_m31(remainder_bits_tmp_e5099_28);
    eval.set_col(28, remainder_bits_col28);
    let wg_v144 = eval.u16_from_m31(remainder_bits_col28);
    let wg_v145 = eval.u16_and(wg_v144, 2);
    let partial_limb_msb_tmp_e5099_29 = eval.u16_shr(wg_v145, 1);
    let partial_limb_msb_col29 = eval.u16_as_m31(partial_limb_msb_tmp_e5099_29);
    eval.set_col(29, partial_limb_msb_col29);
    eval.set_sub_input_word(11, op0_id_col22);
    eval.set_lookup_word(44, m31_1662111297);
    eval.set_lookup_word(45, op0_id_col22);
    eval.set_lookup_word(46, op0_limb_0_col25);
    eval.set_lookup_word(47, op0_limb_1_col26);
    eval.set_lookup_word(48, op0_limb_2_col27);
    let wg_v146 = eval.m31_add(
        remainder_bits_col28,
        decode_small_sign_output_tmp_e5099_27[2],
    );
    eval.set_lookup_word(49, wg_v146);
    eval.set_lookup_word(50, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(51, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(52, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(53, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(54, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(55, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(56, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(57, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(58, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(59, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(60, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(61, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(62, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(63, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(64, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(65, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(66, decode_small_sign_output_tmp_e5099_27[3]);
    eval.set_lookup_word(67, decode_small_sign_output_tmp_e5099_27[4]);
    eval.set_lookup_word(68, m31_0);
    eval.set_lookup_word(69, m31_0);
    eval.set_lookup_word(70, m31_0);
    eval.set_lookup_word(71, m31_0);
    eval.set_lookup_word(72, m31_0);
    eval.set_lookup_word(73, decode_small_sign_output_tmp_e5099_27[5]);
    let wg_v147 = eval.m31_mul(op0_limb_1_col26, m31_512);
    let wg_v148 = eval.m31_add(op0_limb_0_col25, wg_v147);
    let wg_v149 = eval.m31_mul(op0_limb_2_col27, m31_262144);
    let wg_v150 = eval.m31_add(wg_v148, wg_v149);
    let wg_v151 = eval.m31_mul(remainder_bits_col28, m31_134217728);
    let wg_v152 = eval.m31_add(wg_v150, wg_v151);
    let wg_v153 = eval.m31_sub(wg_v152, msb_col23);
    let wg_v154 = eval.m31_mul(m31_536870912, mid_limbs_set_col24);
    let wg_v155 = eval.m31_sub(wg_v153, wg_v154);
    let read_small_output_tmp_e5099_31 = (wg_v155, op0_id_col22);
    let wg_v156 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_e5099_11.0[2],
    );
    let memory_address_to_id_value_tmp_e5099_32 = eval.mem_addr_to_id(wg_v156);
    let op1_id_col30 = memory_address_to_id_value_tmp_e5099_32;
    eval.set_col(30, op1_id_col30);
    let wg_v157 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_e5099_11.0[2],
    );
    eval.set_sub_input_word(9, wg_v157);
    eval.set_lookup_word(74, m31_1444891767);
    let wg_v158 = eval.m31_add(
        mem1_base_col13,
        decode_instruction_7785f_output_tmp_e5099_11.0[2],
    );
    eval.set_lookup_word(75, wg_v158);
    eval.set_lookup_word(76, op1_id_col30);
    let memory_id_to_big_value_tmp_e5099_34 = eval.mem_id_to_value(op1_id_col30);
    let wg_v159 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 27);
    let msb_tmp_e5099_35 = eval.m31_eq(wg_v159, m31_256);
    let msb_col31 = eval.mask_as_m31(msb_tmp_e5099_35);
    eval.set_col(31, msb_col31);
    let wg_v160 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 20);
    let wg_v161 = eval.m31_eq(wg_v160, m31_511);
    let mid_limbs_set_tmp_e5099_36 = eval.mask_and(wg_v161, msb_tmp_e5099_35);
    let mid_limbs_set_col32 = eval.mask_as_m31(mid_limbs_set_tmp_e5099_36);
    eval.set_col(32, mid_limbs_set_col32);
    let wg_v162 = eval.m31_mul(mid_limbs_set_col32, m31_508);
    let wg_v163 = eval.m31_mul(mid_limbs_set_col32, m31_511);
    let wg_v164 = eval.m31_mul(msb_col31, m31_136);
    let wg_v165 = eval.m31_sub(wg_v164, mid_limbs_set_col32);
    let wg_v166 = eval.m31_mul(msb_col31, m31_256);
    let decode_small_sign_output_tmp_e5099_37 = [
        msb_col31,
        mid_limbs_set_col32,
        wg_v162,
        wg_v163,
        wg_v165,
        wg_v166,
    ];
    let op1_limb_0_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 0);
    eval.set_col(33, op1_limb_0_col33);
    let op1_limb_1_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 1);
    eval.set_col(34, op1_limb_1_col34);
    let op1_limb_2_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 2);
    eval.set_col(35, op1_limb_2_col35);
    let wg_v167 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e5099_34.clone(), 3);
    let wg_v168 = eval.u16_from_m31(wg_v167);
    let remainder_bits_tmp_e5099_38 = eval.u16_and(wg_v168, 3);
    let remainder_bits_col36 = eval.u16_as_m31(remainder_bits_tmp_e5099_38);
    eval.set_col(36, remainder_bits_col36);
    let wg_v169 = eval.u16_from_m31(remainder_bits_col36);
    let wg_v170 = eval.u16_and(wg_v169, 2);
    let partial_limb_msb_tmp_e5099_39 = eval.u16_shr(wg_v170, 1);
    let partial_limb_msb_col37 = eval.u16_as_m31(partial_limb_msb_tmp_e5099_39);
    eval.set_col(37, partial_limb_msb_col37);
    eval.set_sub_input_word(12, op1_id_col30);
    eval.set_lookup_word(77, m31_1662111297);
    eval.set_lookup_word(78, op1_id_col30);
    eval.set_lookup_word(79, op1_limb_0_col33);
    eval.set_lookup_word(80, op1_limb_1_col34);
    eval.set_lookup_word(81, op1_limb_2_col35);
    let wg_v171 = eval.m31_add(
        remainder_bits_col36,
        decode_small_sign_output_tmp_e5099_37[2],
    );
    eval.set_lookup_word(82, wg_v171);
    eval.set_lookup_word(83, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(84, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(85, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(86, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(87, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(88, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(89, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(90, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(91, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(92, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(93, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(94, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(95, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(96, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(97, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(98, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(99, decode_small_sign_output_tmp_e5099_37[3]);
    eval.set_lookup_word(100, decode_small_sign_output_tmp_e5099_37[4]);
    eval.set_lookup_word(101, m31_0);
    eval.set_lookup_word(102, m31_0);
    eval.set_lookup_word(103, m31_0);
    eval.set_lookup_word(104, m31_0);
    eval.set_lookup_word(105, m31_0);
    eval.set_lookup_word(106, decode_small_sign_output_tmp_e5099_37[5]);
    let wg_v172 = eval.m31_mul(op1_limb_1_col34, m31_512);
    let wg_v173 = eval.m31_add(op1_limb_0_col33, wg_v172);
    let wg_v174 = eval.m31_mul(op1_limb_2_col35, m31_262144);
    let wg_v175 = eval.m31_add(wg_v173, wg_v174);
    let wg_v176 = eval.m31_mul(remainder_bits_col36, m31_134217728);
    let wg_v177 = eval.m31_add(wg_v175, wg_v176);
    let wg_v178 = eval.m31_sub(wg_v177, msb_col31);
    let wg_v179 = eval.m31_mul(m31_536870912, mid_limbs_set_col32);
    let wg_v180 = eval.m31_sub(wg_v178, wg_v179);
    let read_small_output_tmp_e5099_41 = (wg_v180, op1_id_col30);
    let enabler_col38 = eval.enabler();
    eval.set_col(38, enabler_col38);
    eval.set_lookup_word(107, m31_428564188);
    eval.set_lookup_word(108, input_pc_col0);
    eval.set_lookup_word(109, input_ap_col1);
    eval.set_lookup_word(110, input_fp_col2);
    eval.set_lookup_word(111, m31_428564188);
    let wg_v181 = eval.m31_add(input_pc_col0, m31_1);
    let wg_v182 = eval.m31_add(wg_v181, op1_imm_col8);
    eval.set_lookup_word(112, wg_v182);
    let wg_v183 = eval.m31_add(input_ap_col1, ap_update_add_1_col10);
    eval.set_lookup_word(113, wg_v183);
    eval.set_lookup_word(114, input_fp_col2);
    eval.set_lookup_word(115, m31_1);
    eval.set_lookup_word(116, enabler_col38);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `add_opcode_small_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
            |(row_index, (row, lookup_data, sub_component_inputs, add_opcode_small_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    add_opcode_small_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                add_opcode_small_row_body(&mut eval);
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

/// Record the `add_opcode_small` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_add_opcode_small() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("add_opcode_small");
    add_opcode_small_row_body(&mut eval);
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

// --- witness-JIT prove-lane accessors (marked additive; layout mirrors LookupData /
// the emitted sub-word order; fenced by the prove-accessor parity gate) ---------------

crate::jit_sub_accessors!(N_SUB_INPUT_WORDS, n_addr = 3, n_id = 3);
