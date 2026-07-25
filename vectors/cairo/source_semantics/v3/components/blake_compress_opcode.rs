// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::blake_compress_opcode::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    blake_round, memory_address_to_id, memory_id_to_big, range_check_7_2_5, triple_xor_32,
    verify_bitwise_xor_8, verify_instruction,
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
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
        blake_round_state: &blake_round::ClaimGenerator,
        triple_xor_32_state: &triple_xor_32::ClaimGenerator,
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
            range_check_7_2_5_state,
            verify_bitwise_xor_8_state,
            blake_round_state,
            triple_xor_32_state,
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
        for inputs in sub_component_inputs.range_check_7_2_5 {
            add_inputs(range_check_7_2_5_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.blake_round {
            add_inputs(blake_round_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.triple_xor_32 {
            add_inputs(triple_xor_32_state, &inputs, inputs.len() * N_LANES, 0);
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 20],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 20],
    range_check_7_2_5: [Vec<range_check_7_2_5::PackedInputType>; 17],
    verify_bitwise_xor_8: [Vec<verify_bitwise_xor_8::PackedInputType>; 4],
    blake_round: [Vec<blake_round::PackedInputType>; 10],
    triple_xor_32: [Vec<triple_xor_32::PackedInputType>; 8],
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
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
    blake_round_state: &blake_round::ClaimGenerator,
    triple_xor_32_state: &triple_xor_32::ClaimGenerator,
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
    let M31_10 = PackedM31::broadcast(M31::from(10));
    let M31_112558620 = PackedM31::broadcast(M31::from(112558620));
    let M31_127 = PackedM31::broadcast(M31::from(127));
    let M31_128 = PackedM31::broadcast(M31::from(128));
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_14 = PackedM31::broadcast(M31::from(14));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_15470 = PackedM31::broadcast(M31::from(15470));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_2048 = PackedM31::broadcast(M31::from(2048));
    let M31_23520 = PackedM31::broadcast(M31::from(23520));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_26764 = PackedM31::broadcast(M31::from(26764));
    let M31_27145 = PackedM31::broadcast(M31::from(27145));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_371240602 = PackedM31::broadcast(M31::from(371240602));
    let M31_39685 = PackedM31::broadcast(M31::from(39685));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_40528774 = PackedM31::broadcast(M31::from(40528774));
    let M31_42319 = PackedM31::broadcast(M31::from(42319));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_44677 = PackedM31::broadcast(M31::from(44677));
    let M31_47975 = PackedM31::broadcast(M31::from(47975));
    let M31_5 = PackedM31::broadcast(M31::from(5));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_52505 = PackedM31::broadcast(M31::from(52505));
    let M31_55723 = PackedM31::broadcast(M31::from(55723));
    let M31_57468 = PackedM31::broadcast(M31::from(57468));
    let M31_58983 = PackedM31::broadcast(M31::from(58983));
    let M31_6 = PackedM31::broadcast(M31::from(6));
    let M31_62322 = PackedM31::broadcast(M31::from(62322));
    let M31_62778 = PackedM31::broadcast(M31::from(62778));
    let M31_64 = PackedM31::broadcast(M31::from(64));
    let M31_7 = PackedM31::broadcast(M31::from(7));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let M31_8067 = PackedM31::broadcast(M31::from(8067));
    let M31_81 = PackedM31::broadcast(M31::from(81));
    let M31_82 = PackedM31::broadcast(M31::from(82));
    let M31_9 = PackedM31::broadcast(M31::from(9));
    let M31_9812 = PackedM31::broadcast(M31::from(9812));
    let M31_990559919 = PackedM31::broadcast(M31::from(990559919));
    let UInt16_0 = PackedUInt16::broadcast(UInt16::from(0));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_127 = PackedUInt16::broadcast(UInt16::from(127));
    let UInt16_13 = PackedUInt16::broadcast(UInt16::from(13));
    let UInt16_14 = PackedUInt16::broadcast(UInt16::from(14));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
    let UInt16_31 = PackedUInt16::broadcast(UInt16::from(31));
    let UInt16_4 = PackedUInt16::broadcast(UInt16::from(4));
    let UInt16_5 = PackedUInt16::broadcast(UInt16::from(5));
    let UInt16_6 = PackedUInt16::broadcast(UInt16::from(6));
    let UInt16_7 = PackedUInt16::broadcast(UInt16::from(7));
    let UInt16_8 = PackedUInt16::broadcast(UInt16::from(8));
    let UInt16_81 = PackedUInt16::broadcast(UInt16::from(81));
    let UInt16_82 = PackedUInt16::broadcast(UInt16::from(82));
    let UInt16_9 = PackedUInt16::broadcast(UInt16::from(9));
    let UInt32_1013904242 = PackedUInt32::broadcast(UInt32::from(1013904242));
    let UInt32_1541459225 = PackedUInt32::broadcast(UInt32::from(1541459225));
    let UInt32_1779033703 = PackedUInt32::broadcast(UInt32::from(1779033703));
    let UInt32_2600822924 = PackedUInt32::broadcast(UInt32::from(2600822924));
    let UInt32_2773480762 = PackedUInt32::broadcast(UInt32::from(2773480762));
    let UInt32_3144134277 = PackedUInt32::broadcast(UInt32::from(3144134277));
    let seq = Seq::new(log_size);
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
            |(row_index, (row, lookup_data, sub_component_inputs, blake_compress_opcode_input))| {
                let seq = seq.packed_at(row_index);
                let input_pc_col0 = blake_compress_opcode_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = blake_compress_opcode_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = blake_compress_opcode_input.fp;
                *row[2] = input_fp_col2;

                // Decode Blake Opcode.

                // Decode Instruction.

                let memory_address_to_id_value_tmp_40cd9_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_40cd9_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_0);
                let offset0_tmp_40cd9_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_40cd9_2.as_m31();
                *row[3] = offset0_col3;
                let offset1_tmp_40cd9_3 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(1)))
                        >> (UInt16_7))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(2),
                        )) << (UInt16_2)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(3),
                        )) & (UInt16_31))
                            << (UInt16_11)));
                let offset1_col4 = offset1_tmp_40cd9_3.as_m31();
                *row[4] = offset1_col4;
                let offset2_tmp_40cd9_4 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(3)))
                        >> (UInt16_5))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(4),
                        )) << (UInt16_4)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(5),
                        )) & (UInt16_7))
                            << (UInt16_13)));
                let offset2_col5 = offset2_tmp_40cd9_4.as_m31();
                *row[5] = offset2_col5;
                let dst_base_fp_tmp_40cd9_5 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col6 = dst_base_fp_tmp_40cd9_5.as_m31();
                *row[6] = dst_base_fp_col6;
                let op0_base_fp_tmp_40cd9_6 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_1))
                        & (UInt16_1));
                let op0_base_fp_col7 = op0_base_fp_tmp_40cd9_6.as_m31();
                *row[7] = op0_base_fp_col7;
                let op1_base_fp_tmp_40cd9_7 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_3))
                        & (UInt16_1));
                let op1_base_fp_col8 = op1_base_fp_tmp_40cd9_7.as_m31();
                *row[8] = op1_base_fp_col8;
                let ap_update_add_1_tmp_40cd9_8 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_40cd9_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col9 = ap_update_add_1_tmp_40cd9_8.as_m31();
                *row[9] = ap_update_add_1_col9;
                let opcode_extension_col10 = memory_id_to_big_value_tmp_40cd9_1.get_m31(7);
                *row[10] = opcode_extension_col10;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, offset1_col4, offset2_col5],
                    [
                        (((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                            + ((op1_base_fp_col8) * (M31_64)))
                            + (((M31_1) - (op1_base_fp_col8)) * (M31_128))),
                        ((ap_update_add_1_col9) * (M31_32)),
                    ],
                    opcode_extension_col10,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    offset0_col3,
                    offset1_col4,
                    offset2_col5,
                    (((((dst_base_fp_col6) * (M31_8)) + ((op0_base_fp_col7) * (M31_16)))
                        + ((op1_base_fp_col8) * (M31_64)))
                        + (((M31_1) - (op1_base_fp_col8)) * (M31_128))),
                    ((ap_update_add_1_col9) * (M31_32)),
                    opcode_extension_col10,
                ];
                let decode_instruction_30129_output_tmp_40cd9_9 = (
                    [
                        ((offset0_col3) - (M31_32768)),
                        ((offset1_col4) - (M31_32768)),
                        ((offset2_col5) - (M31_32768)),
                    ],
                    [
                        dst_base_fp_col6,
                        op0_base_fp_col7,
                        M31_0,
                        op1_base_fp_col8,
                        ((M31_1) - (op1_base_fp_col8)),
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        ap_update_add_1_col9,
                        M31_0,
                        M31_0,
                        M31_0,
                    ],
                    opcode_extension_col10,
                );

                let mem0_base_col11 = (((op0_base_fp_col7) * (input_fp_col2))
                    + (((M31_1) - (op0_base_fp_col7)) * (input_ap_col1)));
                *row[11] = mem0_base_col11;

                // Read Positive Num Bits 29.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_10 = memory_address_to_id_state
                    .deduce_output(
                        ((mem0_base_col11) + (decode_instruction_30129_output_tmp_40cd9_9.0[1])),
                    );
                let op0_id_col12 = memory_address_to_id_value_tmp_40cd9_10;
                *row[12] = op0_id_col12;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem0_base_col11) + (decode_instruction_30129_output_tmp_40cd9_9.0[1]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem0_base_col11) + (decode_instruction_30129_output_tmp_40cd9_9.0[1])),
                    op0_id_col12,
                ];

                // Read Positive Known Id Num Bits 29.

                let memory_id_to_big_value_tmp_40cd9_12 =
                    memory_id_to_big_state.deduce_output(op0_id_col12);
                let op0_limb_0_col13 = memory_id_to_big_value_tmp_40cd9_12.get_m31(0);
                *row[13] = op0_limb_0_col13;
                let op0_limb_1_col14 = memory_id_to_big_value_tmp_40cd9_12.get_m31(1);
                *row[14] = op0_limb_1_col14;
                let op0_limb_2_col15 = memory_id_to_big_value_tmp_40cd9_12.get_m31(2);
                *row[15] = op0_limb_2_col15;
                let op0_limb_3_col16 = memory_id_to_big_value_tmp_40cd9_12.get_m31(3);
                *row[16] = op0_limb_3_col16;

                // Range Check Last Limb Bits In Ms Limb 2.

                // Cond Range Check 2.

                let partial_limb_msb_tmp_40cd9_13 =
                    (((PackedUInt16::from_m31(op0_limb_3_col16)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col17 = partial_limb_msb_tmp_40cd9_13.as_m31();
                *row[17] = partial_limb_msb_col17;

                *sub_component_inputs.memory_id_to_big[0] = op0_id_col12;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    op0_id_col12,
                    op0_limb_0_col13,
                    op0_limb_1_col14,
                    op0_limb_2_col15,
                    op0_limb_3_col16,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];
                let read_positive_known_id_num_bits_29_output_tmp_40cd9_15 =
                    PackedFelt252::from_limbs([
                        op0_limb_0_col13,
                        op0_limb_1_col14,
                        op0_limb_2_col15,
                        op0_limb_3_col16,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                    ]);

                let read_positive_num_bits_29_output_tmp_40cd9_16 = (
                    read_positive_known_id_num_bits_29_output_tmp_40cd9_15,
                    op0_id_col12,
                );

                let mem1_base_col18 = (((op1_base_fp_col8) * (input_fp_col2))
                    + ((decode_instruction_30129_output_tmp_40cd9_9.1[4]) * (input_ap_col1)));
                *row[18] = mem1_base_col18;

                // Read Positive Num Bits 29.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_17 = memory_address_to_id_state
                    .deduce_output(
                        ((mem1_base_col18) + (decode_instruction_30129_output_tmp_40cd9_9.0[2])),
                    );
                let op1_id_col19 = memory_address_to_id_value_tmp_40cd9_17;
                *row[19] = op1_id_col19;
                *sub_component_inputs.memory_address_to_id[1] =
                    ((mem1_base_col18) + (decode_instruction_30129_output_tmp_40cd9_9.0[2]));
                *lookup_data.memory_address_to_id_3 = [
                    M31_1444891767,
                    ((mem1_base_col18) + (decode_instruction_30129_output_tmp_40cd9_9.0[2])),
                    op1_id_col19,
                ];

                // Read Positive Known Id Num Bits 29.

                let memory_id_to_big_value_tmp_40cd9_19 =
                    memory_id_to_big_state.deduce_output(op1_id_col19);
                let op1_limb_0_col20 = memory_id_to_big_value_tmp_40cd9_19.get_m31(0);
                *row[20] = op1_limb_0_col20;
                let op1_limb_1_col21 = memory_id_to_big_value_tmp_40cd9_19.get_m31(1);
                *row[21] = op1_limb_1_col21;
                let op1_limb_2_col22 = memory_id_to_big_value_tmp_40cd9_19.get_m31(2);
                *row[22] = op1_limb_2_col22;
                let op1_limb_3_col23 = memory_id_to_big_value_tmp_40cd9_19.get_m31(3);
                *row[23] = op1_limb_3_col23;

                // Range Check Last Limb Bits In Ms Limb 2.

                // Cond Range Check 2.

                let partial_limb_msb_tmp_40cd9_20 =
                    (((PackedUInt16::from_m31(op1_limb_3_col23)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col24 = partial_limb_msb_tmp_40cd9_20.as_m31();
                *row[24] = partial_limb_msb_col24;

                *sub_component_inputs.memory_id_to_big[1] = op1_id_col19;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    op1_id_col19,
                    op1_limb_0_col20,
                    op1_limb_1_col21,
                    op1_limb_2_col22,
                    op1_limb_3_col23,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];
                let read_positive_known_id_num_bits_29_output_tmp_40cd9_22 =
                    PackedFelt252::from_limbs([
                        op1_limb_0_col20,
                        op1_limb_1_col21,
                        op1_limb_2_col22,
                        op1_limb_3_col23,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                    ]);

                let read_positive_num_bits_29_output_tmp_40cd9_23 = (
                    read_positive_known_id_num_bits_29_output_tmp_40cd9_22,
                    op1_id_col19,
                );

                // Read Positive Num Bits 29.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_24 =
                    memory_address_to_id_state.deduce_output(input_ap_col1);
                let ap_id_col25 = memory_address_to_id_value_tmp_40cd9_24;
                *row[25] = ap_id_col25;
                *sub_component_inputs.memory_address_to_id[2] = input_ap_col1;
                *lookup_data.memory_address_to_id_5 = [M31_1444891767, input_ap_col1, ap_id_col25];

                // Read Positive Known Id Num Bits 29.

                let memory_id_to_big_value_tmp_40cd9_26 =
                    memory_id_to_big_state.deduce_output(ap_id_col25);
                let ap_limb_0_col26 = memory_id_to_big_value_tmp_40cd9_26.get_m31(0);
                *row[26] = ap_limb_0_col26;
                let ap_limb_1_col27 = memory_id_to_big_value_tmp_40cd9_26.get_m31(1);
                *row[27] = ap_limb_1_col27;
                let ap_limb_2_col28 = memory_id_to_big_value_tmp_40cd9_26.get_m31(2);
                *row[28] = ap_limb_2_col28;
                let ap_limb_3_col29 = memory_id_to_big_value_tmp_40cd9_26.get_m31(3);
                *row[29] = ap_limb_3_col29;

                // Range Check Last Limb Bits In Ms Limb 2.

                // Cond Range Check 2.

                let partial_limb_msb_tmp_40cd9_27 =
                    (((PackedUInt16::from_m31(ap_limb_3_col29)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col30 = partial_limb_msb_tmp_40cd9_27.as_m31();
                *row[30] = partial_limb_msb_col30;

                *sub_component_inputs.memory_id_to_big[2] = ap_id_col25;
                *lookup_data.memory_id_to_big_6 = [
                    M31_1662111297,
                    ap_id_col25,
                    ap_limb_0_col26,
                    ap_limb_1_col27,
                    ap_limb_2_col28,
                    ap_limb_3_col29,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];
                let read_positive_known_id_num_bits_29_output_tmp_40cd9_29 =
                    PackedFelt252::from_limbs([
                        ap_limb_0_col26,
                        ap_limb_1_col27,
                        ap_limb_2_col28,
                        ap_limb_3_col29,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                    ]);

                let read_positive_num_bits_29_output_tmp_40cd9_30 = (
                    read_positive_known_id_num_bits_29_output_tmp_40cd9_29,
                    ap_id_col25,
                );

                let mem_dst_base_col31 = (((dst_base_fp_col6) * (input_fp_col2))
                    + (((M31_1) - (dst_base_fp_col6)) * (input_ap_col1)));
                *row[31] = mem_dst_base_col31;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_31 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col31) + (decode_instruction_30129_output_tmp_40cd9_9.0[0])),
                    );
                let memory_id_to_big_value_tmp_40cd9_32 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_31);
                let tmp_40cd9_33 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_32.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col32 = ((((memory_id_to_big_value_tmp_40cd9_32.get_m31(1))
                    - ((tmp_40cd9_33.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_32.get_m31(0)));
                *row[32] = low_16_bits_col32;
                let high_16_bits_col33 = ((((memory_id_to_big_value_tmp_40cd9_32.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_32.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_33.as_m31()));
                *row[33] = high_16_bits_col33;
                let expected_word_tmp_40cd9_34 =
                    PackedUInt32::from_limbs([low_16_bits_col32, high_16_bits_col33]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_35 = ((expected_word_tmp_40cd9_34.low()) >> (UInt16_9));
                let low_7_ms_bits_col34 = low_7_ms_bits_tmp_40cd9_35.as_m31();
                *row[34] = low_7_ms_bits_col34;
                let high_14_ms_bits_tmp_40cd9_36 =
                    ((expected_word_tmp_40cd9_34.high()) >> (UInt16_2));
                let high_14_ms_bits_col35 = high_14_ms_bits_tmp_40cd9_36.as_m31();
                *row[35] = high_14_ms_bits_col35;
                let high_2_ls_bits_tmp_40cd9_37 =
                    ((high_16_bits_col33) - ((high_14_ms_bits_col35) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_38 = ((high_14_ms_bits_tmp_40cd9_36) >> (UInt16_9));
                let high_5_ms_bits_col36 = high_5_ms_bits_tmp_40cd9_38.as_m31();
                *row[36] = high_5_ms_bits_col36;
                *sub_component_inputs.range_check_7_2_5[0] = [
                    low_7_ms_bits_col34,
                    high_2_ls_bits_tmp_40cd9_37,
                    high_5_ms_bits_col36,
                ];
                *lookup_data.range_check_7_2_5_7 = [
                    M31_371240602,
                    low_7_ms_bits_col34,
                    high_2_ls_bits_tmp_40cd9_37,
                    high_5_ms_bits_col36,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_39 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col31) + (decode_instruction_30129_output_tmp_40cd9_9.0[0])),
                    );
                let dst_id_col37 = memory_address_to_id_value_tmp_40cd9_39;
                *row[37] = dst_id_col37;
                *sub_component_inputs.memory_address_to_id[3] =
                    ((mem_dst_base_col31) + (decode_instruction_30129_output_tmp_40cd9_9.0[0]));
                *lookup_data.memory_address_to_id_8 = [
                    M31_1444891767,
                    ((mem_dst_base_col31) + (decode_instruction_30129_output_tmp_40cd9_9.0[0])),
                    dst_id_col37,
                ];

                *sub_component_inputs.memory_id_to_big[3] = dst_id_col37;
                *lookup_data.memory_id_to_big_9 = [
                    M31_1662111297,
                    dst_id_col37,
                    ((low_16_bits_col32) - ((low_7_ms_bits_col34) * (M31_512))),
                    ((low_7_ms_bits_col34) + ((high_2_ls_bits_tmp_40cd9_37) * (M31_128))),
                    ((high_14_ms_bits_col35) - ((high_5_ms_bits_col36) * (M31_512))),
                    high_5_ms_bits_col36,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_41 = expected_word_tmp_40cd9_34;

                let decode_blake_opcode_output_tmp_40cd9_42 = (
                    [
                        ((((op0_limb_0_col13) + ((op0_limb_1_col14) * (M31_512)))
                            + ((op0_limb_2_col15) * (M31_262144)))
                            + ((op0_limb_3_col16) * (M31_134217728))),
                        ((((op1_limb_0_col20) + ((op1_limb_1_col21) * (M31_512)))
                            + ((op1_limb_2_col22) * (M31_262144)))
                            + ((op1_limb_3_col23) * (M31_134217728))),
                        ((((ap_limb_0_col26) + ((ap_limb_1_col27) * (M31_512)))
                            + ((ap_limb_2_col28) * (M31_262144)))
                            + ((ap_limb_3_col29) * (M31_134217728))),
                    ],
                    read_u_32_output_tmp_40cd9_41,
                    [
                        PackedBool::from_m31(ap_update_add_1_col9),
                        PackedBool::from_m31(((opcode_extension_col10) - (M31_1))),
                    ],
                );

                // Create Blake Round Input.

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_43 = memory_address_to_id_state
                    .deduce_output(decode_blake_opcode_output_tmp_40cd9_42.0[0]);
                let memory_id_to_big_value_tmp_40cd9_44 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_43);
                let tmp_40cd9_45 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_44.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col38 = ((((memory_id_to_big_value_tmp_40cd9_44.get_m31(1))
                    - ((tmp_40cd9_45.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_44.get_m31(0)));
                *row[38] = low_16_bits_col38;
                let high_16_bits_col39 = ((((memory_id_to_big_value_tmp_40cd9_44.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_44.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_45.as_m31()));
                *row[39] = high_16_bits_col39;
                let expected_word_tmp_40cd9_46 =
                    PackedUInt32::from_limbs([low_16_bits_col38, high_16_bits_col39]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_47 = ((expected_word_tmp_40cd9_46.low()) >> (UInt16_9));
                let low_7_ms_bits_col40 = low_7_ms_bits_tmp_40cd9_47.as_m31();
                *row[40] = low_7_ms_bits_col40;
                let high_14_ms_bits_tmp_40cd9_48 =
                    ((expected_word_tmp_40cd9_46.high()) >> (UInt16_2));
                let high_14_ms_bits_col41 = high_14_ms_bits_tmp_40cd9_48.as_m31();
                *row[41] = high_14_ms_bits_col41;
                let high_2_ls_bits_tmp_40cd9_49 =
                    ((high_16_bits_col39) - ((high_14_ms_bits_col41) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_50 = ((high_14_ms_bits_tmp_40cd9_48) >> (UInt16_9));
                let high_5_ms_bits_col42 = high_5_ms_bits_tmp_40cd9_50.as_m31();
                *row[42] = high_5_ms_bits_col42;
                *sub_component_inputs.range_check_7_2_5[1] = [
                    low_7_ms_bits_col40,
                    high_2_ls_bits_tmp_40cd9_49,
                    high_5_ms_bits_col42,
                ];
                *lookup_data.range_check_7_2_5_10 = [
                    M31_371240602,
                    low_7_ms_bits_col40,
                    high_2_ls_bits_tmp_40cd9_49,
                    high_5_ms_bits_col42,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_51 = memory_address_to_id_state
                    .deduce_output(decode_blake_opcode_output_tmp_40cd9_42.0[0]);
                let state_0_id_col43 = memory_address_to_id_value_tmp_40cd9_51;
                *row[43] = state_0_id_col43;
                *sub_component_inputs.memory_address_to_id[4] =
                    decode_blake_opcode_output_tmp_40cd9_42.0[0];
                *lookup_data.memory_address_to_id_11 = [
                    M31_1444891767,
                    decode_blake_opcode_output_tmp_40cd9_42.0[0],
                    state_0_id_col43,
                ];

                *sub_component_inputs.memory_id_to_big[4] = state_0_id_col43;
                *lookup_data.memory_id_to_big_12 = [
                    M31_1662111297,
                    state_0_id_col43,
                    ((low_16_bits_col38) - ((low_7_ms_bits_col40) * (M31_512))),
                    ((low_7_ms_bits_col40) + ((high_2_ls_bits_tmp_40cd9_49) * (M31_128))),
                    ((high_14_ms_bits_col41) - ((high_5_ms_bits_col42) * (M31_512))),
                    high_5_ms_bits_col42,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_53 = expected_word_tmp_40cd9_46;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_54 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_1)));
                let memory_id_to_big_value_tmp_40cd9_55 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_54);
                let tmp_40cd9_56 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_55.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col44 = ((((memory_id_to_big_value_tmp_40cd9_55.get_m31(1))
                    - ((tmp_40cd9_56.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_55.get_m31(0)));
                *row[44] = low_16_bits_col44;
                let high_16_bits_col45 = ((((memory_id_to_big_value_tmp_40cd9_55.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_55.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_56.as_m31()));
                *row[45] = high_16_bits_col45;
                let expected_word_tmp_40cd9_57 =
                    PackedUInt32::from_limbs([low_16_bits_col44, high_16_bits_col45]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_58 = ((expected_word_tmp_40cd9_57.low()) >> (UInt16_9));
                let low_7_ms_bits_col46 = low_7_ms_bits_tmp_40cd9_58.as_m31();
                *row[46] = low_7_ms_bits_col46;
                let high_14_ms_bits_tmp_40cd9_59 =
                    ((expected_word_tmp_40cd9_57.high()) >> (UInt16_2));
                let high_14_ms_bits_col47 = high_14_ms_bits_tmp_40cd9_59.as_m31();
                *row[47] = high_14_ms_bits_col47;
                let high_2_ls_bits_tmp_40cd9_60 =
                    ((high_16_bits_col45) - ((high_14_ms_bits_col47) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_61 = ((high_14_ms_bits_tmp_40cd9_59) >> (UInt16_9));
                let high_5_ms_bits_col48 = high_5_ms_bits_tmp_40cd9_61.as_m31();
                *row[48] = high_5_ms_bits_col48;
                *sub_component_inputs.range_check_7_2_5[2] = [
                    low_7_ms_bits_col46,
                    high_2_ls_bits_tmp_40cd9_60,
                    high_5_ms_bits_col48,
                ];
                *lookup_data.range_check_7_2_5_13 = [
                    M31_371240602,
                    low_7_ms_bits_col46,
                    high_2_ls_bits_tmp_40cd9_60,
                    high_5_ms_bits_col48,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_62 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_1)));
                let state_1_id_col49 = memory_address_to_id_value_tmp_40cd9_62;
                *row[49] = state_1_id_col49;
                *sub_component_inputs.memory_address_to_id[5] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_1));
                *lookup_data.memory_address_to_id_14 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_1)),
                    state_1_id_col49,
                ];

                *sub_component_inputs.memory_id_to_big[5] = state_1_id_col49;
                *lookup_data.memory_id_to_big_15 = [
                    M31_1662111297,
                    state_1_id_col49,
                    ((low_16_bits_col44) - ((low_7_ms_bits_col46) * (M31_512))),
                    ((low_7_ms_bits_col46) + ((high_2_ls_bits_tmp_40cd9_60) * (M31_128))),
                    ((high_14_ms_bits_col47) - ((high_5_ms_bits_col48) * (M31_512))),
                    high_5_ms_bits_col48,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_64 = expected_word_tmp_40cd9_57;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_65 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_2)));
                let memory_id_to_big_value_tmp_40cd9_66 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_65);
                let tmp_40cd9_67 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_66.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col50 = ((((memory_id_to_big_value_tmp_40cd9_66.get_m31(1))
                    - ((tmp_40cd9_67.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_66.get_m31(0)));
                *row[50] = low_16_bits_col50;
                let high_16_bits_col51 = ((((memory_id_to_big_value_tmp_40cd9_66.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_66.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_67.as_m31()));
                *row[51] = high_16_bits_col51;
                let expected_word_tmp_40cd9_68 =
                    PackedUInt32::from_limbs([low_16_bits_col50, high_16_bits_col51]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_69 = ((expected_word_tmp_40cd9_68.low()) >> (UInt16_9));
                let low_7_ms_bits_col52 = low_7_ms_bits_tmp_40cd9_69.as_m31();
                *row[52] = low_7_ms_bits_col52;
                let high_14_ms_bits_tmp_40cd9_70 =
                    ((expected_word_tmp_40cd9_68.high()) >> (UInt16_2));
                let high_14_ms_bits_col53 = high_14_ms_bits_tmp_40cd9_70.as_m31();
                *row[53] = high_14_ms_bits_col53;
                let high_2_ls_bits_tmp_40cd9_71 =
                    ((high_16_bits_col51) - ((high_14_ms_bits_col53) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_72 = ((high_14_ms_bits_tmp_40cd9_70) >> (UInt16_9));
                let high_5_ms_bits_col54 = high_5_ms_bits_tmp_40cd9_72.as_m31();
                *row[54] = high_5_ms_bits_col54;
                *sub_component_inputs.range_check_7_2_5[3] = [
                    low_7_ms_bits_col52,
                    high_2_ls_bits_tmp_40cd9_71,
                    high_5_ms_bits_col54,
                ];
                *lookup_data.range_check_7_2_5_16 = [
                    M31_371240602,
                    low_7_ms_bits_col52,
                    high_2_ls_bits_tmp_40cd9_71,
                    high_5_ms_bits_col54,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_73 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_2)));
                let state_2_id_col55 = memory_address_to_id_value_tmp_40cd9_73;
                *row[55] = state_2_id_col55;
                *sub_component_inputs.memory_address_to_id[6] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_2));
                *lookup_data.memory_address_to_id_17 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_2)),
                    state_2_id_col55,
                ];

                *sub_component_inputs.memory_id_to_big[6] = state_2_id_col55;
                *lookup_data.memory_id_to_big_18 = [
                    M31_1662111297,
                    state_2_id_col55,
                    ((low_16_bits_col50) - ((low_7_ms_bits_col52) * (M31_512))),
                    ((low_7_ms_bits_col52) + ((high_2_ls_bits_tmp_40cd9_71) * (M31_128))),
                    ((high_14_ms_bits_col53) - ((high_5_ms_bits_col54) * (M31_512))),
                    high_5_ms_bits_col54,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_75 = expected_word_tmp_40cd9_68;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_76 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_3)));
                let memory_id_to_big_value_tmp_40cd9_77 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_76);
                let tmp_40cd9_78 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_77.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col56 = ((((memory_id_to_big_value_tmp_40cd9_77.get_m31(1))
                    - ((tmp_40cd9_78.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_77.get_m31(0)));
                *row[56] = low_16_bits_col56;
                let high_16_bits_col57 = ((((memory_id_to_big_value_tmp_40cd9_77.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_77.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_78.as_m31()));
                *row[57] = high_16_bits_col57;
                let expected_word_tmp_40cd9_79 =
                    PackedUInt32::from_limbs([low_16_bits_col56, high_16_bits_col57]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_80 = ((expected_word_tmp_40cd9_79.low()) >> (UInt16_9));
                let low_7_ms_bits_col58 = low_7_ms_bits_tmp_40cd9_80.as_m31();
                *row[58] = low_7_ms_bits_col58;
                let high_14_ms_bits_tmp_40cd9_81 =
                    ((expected_word_tmp_40cd9_79.high()) >> (UInt16_2));
                let high_14_ms_bits_col59 = high_14_ms_bits_tmp_40cd9_81.as_m31();
                *row[59] = high_14_ms_bits_col59;
                let high_2_ls_bits_tmp_40cd9_82 =
                    ((high_16_bits_col57) - ((high_14_ms_bits_col59) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_83 = ((high_14_ms_bits_tmp_40cd9_81) >> (UInt16_9));
                let high_5_ms_bits_col60 = high_5_ms_bits_tmp_40cd9_83.as_m31();
                *row[60] = high_5_ms_bits_col60;
                *sub_component_inputs.range_check_7_2_5[4] = [
                    low_7_ms_bits_col58,
                    high_2_ls_bits_tmp_40cd9_82,
                    high_5_ms_bits_col60,
                ];
                *lookup_data.range_check_7_2_5_19 = [
                    M31_371240602,
                    low_7_ms_bits_col58,
                    high_2_ls_bits_tmp_40cd9_82,
                    high_5_ms_bits_col60,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_84 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_3)));
                let state_3_id_col61 = memory_address_to_id_value_tmp_40cd9_84;
                *row[61] = state_3_id_col61;
                *sub_component_inputs.memory_address_to_id[7] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_3));
                *lookup_data.memory_address_to_id_20 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_3)),
                    state_3_id_col61,
                ];

                *sub_component_inputs.memory_id_to_big[7] = state_3_id_col61;
                *lookup_data.memory_id_to_big_21 = [
                    M31_1662111297,
                    state_3_id_col61,
                    ((low_16_bits_col56) - ((low_7_ms_bits_col58) * (M31_512))),
                    ((low_7_ms_bits_col58) + ((high_2_ls_bits_tmp_40cd9_82) * (M31_128))),
                    ((high_14_ms_bits_col59) - ((high_5_ms_bits_col60) * (M31_512))),
                    high_5_ms_bits_col60,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_86 = expected_word_tmp_40cd9_79;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_87 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_4)));
                let memory_id_to_big_value_tmp_40cd9_88 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_87);
                let tmp_40cd9_89 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_88.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col62 = ((((memory_id_to_big_value_tmp_40cd9_88.get_m31(1))
                    - ((tmp_40cd9_89.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_88.get_m31(0)));
                *row[62] = low_16_bits_col62;
                let high_16_bits_col63 = ((((memory_id_to_big_value_tmp_40cd9_88.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_88.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_89.as_m31()));
                *row[63] = high_16_bits_col63;
                let expected_word_tmp_40cd9_90 =
                    PackedUInt32::from_limbs([low_16_bits_col62, high_16_bits_col63]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_91 = ((expected_word_tmp_40cd9_90.low()) >> (UInt16_9));
                let low_7_ms_bits_col64 = low_7_ms_bits_tmp_40cd9_91.as_m31();
                *row[64] = low_7_ms_bits_col64;
                let high_14_ms_bits_tmp_40cd9_92 =
                    ((expected_word_tmp_40cd9_90.high()) >> (UInt16_2));
                let high_14_ms_bits_col65 = high_14_ms_bits_tmp_40cd9_92.as_m31();
                *row[65] = high_14_ms_bits_col65;
                let high_2_ls_bits_tmp_40cd9_93 =
                    ((high_16_bits_col63) - ((high_14_ms_bits_col65) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_94 = ((high_14_ms_bits_tmp_40cd9_92) >> (UInt16_9));
                let high_5_ms_bits_col66 = high_5_ms_bits_tmp_40cd9_94.as_m31();
                *row[66] = high_5_ms_bits_col66;
                *sub_component_inputs.range_check_7_2_5[5] = [
                    low_7_ms_bits_col64,
                    high_2_ls_bits_tmp_40cd9_93,
                    high_5_ms_bits_col66,
                ];
                *lookup_data.range_check_7_2_5_22 = [
                    M31_371240602,
                    low_7_ms_bits_col64,
                    high_2_ls_bits_tmp_40cd9_93,
                    high_5_ms_bits_col66,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_95 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_4)));
                let state_4_id_col67 = memory_address_to_id_value_tmp_40cd9_95;
                *row[67] = state_4_id_col67;
                *sub_component_inputs.memory_address_to_id[8] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_4));
                *lookup_data.memory_address_to_id_23 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_4)),
                    state_4_id_col67,
                ];

                *sub_component_inputs.memory_id_to_big[8] = state_4_id_col67;
                *lookup_data.memory_id_to_big_24 = [
                    M31_1662111297,
                    state_4_id_col67,
                    ((low_16_bits_col62) - ((low_7_ms_bits_col64) * (M31_512))),
                    ((low_7_ms_bits_col64) + ((high_2_ls_bits_tmp_40cd9_93) * (M31_128))),
                    ((high_14_ms_bits_col65) - ((high_5_ms_bits_col66) * (M31_512))),
                    high_5_ms_bits_col66,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_97 = expected_word_tmp_40cd9_90;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_98 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_5)));
                let memory_id_to_big_value_tmp_40cd9_99 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_98);
                let tmp_40cd9_100 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_99.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col68 = ((((memory_id_to_big_value_tmp_40cd9_99.get_m31(1))
                    - ((tmp_40cd9_100.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_99.get_m31(0)));
                *row[68] = low_16_bits_col68;
                let high_16_bits_col69 = ((((memory_id_to_big_value_tmp_40cd9_99.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_99.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_100.as_m31()));
                *row[69] = high_16_bits_col69;
                let expected_word_tmp_40cd9_101 =
                    PackedUInt32::from_limbs([low_16_bits_col68, high_16_bits_col69]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_102 =
                    ((expected_word_tmp_40cd9_101.low()) >> (UInt16_9));
                let low_7_ms_bits_col70 = low_7_ms_bits_tmp_40cd9_102.as_m31();
                *row[70] = low_7_ms_bits_col70;
                let high_14_ms_bits_tmp_40cd9_103 =
                    ((expected_word_tmp_40cd9_101.high()) >> (UInt16_2));
                let high_14_ms_bits_col71 = high_14_ms_bits_tmp_40cd9_103.as_m31();
                *row[71] = high_14_ms_bits_col71;
                let high_2_ls_bits_tmp_40cd9_104 =
                    ((high_16_bits_col69) - ((high_14_ms_bits_col71) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_105 = ((high_14_ms_bits_tmp_40cd9_103) >> (UInt16_9));
                let high_5_ms_bits_col72 = high_5_ms_bits_tmp_40cd9_105.as_m31();
                *row[72] = high_5_ms_bits_col72;
                *sub_component_inputs.range_check_7_2_5[6] = [
                    low_7_ms_bits_col70,
                    high_2_ls_bits_tmp_40cd9_104,
                    high_5_ms_bits_col72,
                ];
                *lookup_data.range_check_7_2_5_25 = [
                    M31_371240602,
                    low_7_ms_bits_col70,
                    high_2_ls_bits_tmp_40cd9_104,
                    high_5_ms_bits_col72,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_106 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_5)));
                let state_5_id_col73 = memory_address_to_id_value_tmp_40cd9_106;
                *row[73] = state_5_id_col73;
                *sub_component_inputs.memory_address_to_id[9] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_5));
                *lookup_data.memory_address_to_id_26 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_5)),
                    state_5_id_col73,
                ];

                *sub_component_inputs.memory_id_to_big[9] = state_5_id_col73;
                *lookup_data.memory_id_to_big_27 = [
                    M31_1662111297,
                    state_5_id_col73,
                    ((low_16_bits_col68) - ((low_7_ms_bits_col70) * (M31_512))),
                    ((low_7_ms_bits_col70) + ((high_2_ls_bits_tmp_40cd9_104) * (M31_128))),
                    ((high_14_ms_bits_col71) - ((high_5_ms_bits_col72) * (M31_512))),
                    high_5_ms_bits_col72,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_108 = expected_word_tmp_40cd9_101;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_109 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_6)));
                let memory_id_to_big_value_tmp_40cd9_110 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_109);
                let tmp_40cd9_111 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_110.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col74 = ((((memory_id_to_big_value_tmp_40cd9_110.get_m31(1))
                    - ((tmp_40cd9_111.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_110.get_m31(0)));
                *row[74] = low_16_bits_col74;
                let high_16_bits_col75 = ((((memory_id_to_big_value_tmp_40cd9_110.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_110.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_111.as_m31()));
                *row[75] = high_16_bits_col75;
                let expected_word_tmp_40cd9_112 =
                    PackedUInt32::from_limbs([low_16_bits_col74, high_16_bits_col75]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_113 =
                    ((expected_word_tmp_40cd9_112.low()) >> (UInt16_9));
                let low_7_ms_bits_col76 = low_7_ms_bits_tmp_40cd9_113.as_m31();
                *row[76] = low_7_ms_bits_col76;
                let high_14_ms_bits_tmp_40cd9_114 =
                    ((expected_word_tmp_40cd9_112.high()) >> (UInt16_2));
                let high_14_ms_bits_col77 = high_14_ms_bits_tmp_40cd9_114.as_m31();
                *row[77] = high_14_ms_bits_col77;
                let high_2_ls_bits_tmp_40cd9_115 =
                    ((high_16_bits_col75) - ((high_14_ms_bits_col77) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_116 = ((high_14_ms_bits_tmp_40cd9_114) >> (UInt16_9));
                let high_5_ms_bits_col78 = high_5_ms_bits_tmp_40cd9_116.as_m31();
                *row[78] = high_5_ms_bits_col78;
                *sub_component_inputs.range_check_7_2_5[7] = [
                    low_7_ms_bits_col76,
                    high_2_ls_bits_tmp_40cd9_115,
                    high_5_ms_bits_col78,
                ];
                *lookup_data.range_check_7_2_5_28 = [
                    M31_371240602,
                    low_7_ms_bits_col76,
                    high_2_ls_bits_tmp_40cd9_115,
                    high_5_ms_bits_col78,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_117 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_6)));
                let state_6_id_col79 = memory_address_to_id_value_tmp_40cd9_117;
                *row[79] = state_6_id_col79;
                *sub_component_inputs.memory_address_to_id[10] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_6));
                *lookup_data.memory_address_to_id_29 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_6)),
                    state_6_id_col79,
                ];

                *sub_component_inputs.memory_id_to_big[10] = state_6_id_col79;
                *lookup_data.memory_id_to_big_30 = [
                    M31_1662111297,
                    state_6_id_col79,
                    ((low_16_bits_col74) - ((low_7_ms_bits_col76) * (M31_512))),
                    ((low_7_ms_bits_col76) + ((high_2_ls_bits_tmp_40cd9_115) * (M31_128))),
                    ((high_14_ms_bits_col77) - ((high_5_ms_bits_col78) * (M31_512))),
                    high_5_ms_bits_col78,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_119 = expected_word_tmp_40cd9_112;

                // Read U 32.

                let memory_address_to_id_value_tmp_40cd9_120 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_7)));
                let memory_id_to_big_value_tmp_40cd9_121 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_40cd9_120);
                let tmp_40cd9_122 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_40cd9_121.get_m31(1)))
                        >> (UInt16_7));
                let low_16_bits_col80 = ((((memory_id_to_big_value_tmp_40cd9_121.get_m31(1))
                    - ((tmp_40cd9_122.as_m31()) * (M31_128)))
                    * (M31_512))
                    + (memory_id_to_big_value_tmp_40cd9_121.get_m31(0)));
                *row[80] = low_16_bits_col80;
                let high_16_bits_col81 = ((((memory_id_to_big_value_tmp_40cd9_121.get_m31(3))
                    * (M31_2048))
                    + ((memory_id_to_big_value_tmp_40cd9_121.get_m31(2)) * (M31_4)))
                    + (tmp_40cd9_122.as_m31()));
                *row[81] = high_16_bits_col81;
                let expected_word_tmp_40cd9_123 =
                    PackedUInt32::from_limbs([low_16_bits_col80, high_16_bits_col81]);

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_124 =
                    ((expected_word_tmp_40cd9_123.low()) >> (UInt16_9));
                let low_7_ms_bits_col82 = low_7_ms_bits_tmp_40cd9_124.as_m31();
                *row[82] = low_7_ms_bits_col82;
                let high_14_ms_bits_tmp_40cd9_125 =
                    ((expected_word_tmp_40cd9_123.high()) >> (UInt16_2));
                let high_14_ms_bits_col83 = high_14_ms_bits_tmp_40cd9_125.as_m31();
                *row[83] = high_14_ms_bits_col83;
                let high_2_ls_bits_tmp_40cd9_126 =
                    ((high_16_bits_col81) - ((high_14_ms_bits_col83) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_127 = ((high_14_ms_bits_tmp_40cd9_125) >> (UInt16_9));
                let high_5_ms_bits_col84 = high_5_ms_bits_tmp_40cd9_127.as_m31();
                *row[84] = high_5_ms_bits_col84;
                *sub_component_inputs.range_check_7_2_5[8] = [
                    low_7_ms_bits_col82,
                    high_2_ls_bits_tmp_40cd9_126,
                    high_5_ms_bits_col84,
                ];
                *lookup_data.range_check_7_2_5_31 = [
                    M31_371240602,
                    low_7_ms_bits_col82,
                    high_2_ls_bits_tmp_40cd9_126,
                    high_5_ms_bits_col84,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_128 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_7)));
                let state_7_id_col85 = memory_address_to_id_value_tmp_40cd9_128;
                *row[85] = state_7_id_col85;
                *sub_component_inputs.memory_address_to_id[11] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_7));
                *lookup_data.memory_address_to_id_32 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[0]) + (M31_7)),
                    state_7_id_col85,
                ];

                *sub_component_inputs.memory_id_to_big[11] = state_7_id_col85;
                *lookup_data.memory_id_to_big_33 = [
                    M31_1662111297,
                    state_7_id_col85,
                    ((low_16_bits_col80) - ((low_7_ms_bits_col82) * (M31_512))),
                    ((low_7_ms_bits_col82) + ((high_2_ls_bits_tmp_40cd9_126) * (M31_128))),
                    ((high_14_ms_bits_col83) - ((high_5_ms_bits_col84) * (M31_512))),
                    high_5_ms_bits_col84,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let read_u_32_output_tmp_40cd9_130 = expected_word_tmp_40cd9_123;

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_40cd9_131 =
                    ((decode_blake_opcode_output_tmp_40cd9_42.1.low()) >> (UInt16_8));
                let ms_8_bits_col86 = ms_8_bits_tmp_40cd9_131.as_m31();
                *row[86] = ms_8_bits_col86;
                let split_16_low_part_size_8_output_tmp_40cd9_132 = [
                    ((low_16_bits_col32) - ((ms_8_bits_col86) * (M31_256))),
                    ms_8_bits_col86,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_40cd9_133 =
                    ((decode_blake_opcode_output_tmp_40cd9_42.1.high()) >> (UInt16_8));
                let ms_8_bits_col87 = ms_8_bits_tmp_40cd9_133.as_m31();
                *row[87] = ms_8_bits_col87;
                let split_16_low_part_size_8_output_tmp_40cd9_134 = [
                    ((high_16_bits_col33) - ((ms_8_bits_col87) * (M31_256))),
                    ms_8_bits_col87,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_40cd9_135 =
                    ((PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_40cd9_132[0]))
                        ^ (UInt16_127));
                let xor_col88 = xor_tmp_40cd9_135.as_m31();
                *row[88] = xor_col88;
                *sub_component_inputs.verify_bitwise_xor_8[0] = [
                    split_16_low_part_size_8_output_tmp_40cd9_132[0],
                    M31_127,
                    xor_col88,
                ];
                *lookup_data.verify_bitwise_xor_8_34 = [
                    M31_112558620,
                    split_16_low_part_size_8_output_tmp_40cd9_132[0],
                    M31_127,
                    xor_col88,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_40cd9_137 = ((PackedUInt16::from_m31(ms_8_bits_col86)) ^ (UInt16_82));
                let xor_col89 = xor_tmp_40cd9_137.as_m31();
                *row[89] = xor_col89;
                *sub_component_inputs.verify_bitwise_xor_8[1] =
                    [ms_8_bits_col86, M31_82, xor_col89];
                *lookup_data.verify_bitwise_xor_8_35 =
                    [M31_112558620, ms_8_bits_col86, M31_82, xor_col89];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_40cd9_139 =
                    ((PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_40cd9_134[0]))
                        ^ (UInt16_14));
                let xor_col90 = xor_tmp_40cd9_139.as_m31();
                *row[90] = xor_col90;
                *sub_component_inputs.verify_bitwise_xor_8[2] = [
                    split_16_low_part_size_8_output_tmp_40cd9_134[0],
                    M31_14,
                    xor_col90,
                ];
                *lookup_data.verify_bitwise_xor_8_36 = [
                    M31_112558620,
                    split_16_low_part_size_8_output_tmp_40cd9_134[0],
                    M31_14,
                    xor_col90,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_40cd9_141 = ((PackedUInt16::from_m31(ms_8_bits_col87)) ^ (UInt16_81));
                let xor_col91 = xor_tmp_40cd9_141.as_m31();
                *row[91] = xor_col91;
                *sub_component_inputs.verify_bitwise_xor_8[3] =
                    [ms_8_bits_col87, M31_81, xor_col91];
                *lookup_data.verify_bitwise_xor_8_37 =
                    [M31_112558620, ms_8_bits_col87, M31_81, xor_col91];

                let create_blake_round_input_output_tmp_40cd9_143 = [
                    read_u_32_output_tmp_40cd9_53,
                    read_u_32_output_tmp_40cd9_64,
                    read_u_32_output_tmp_40cd9_75,
                    read_u_32_output_tmp_40cd9_86,
                    read_u_32_output_tmp_40cd9_97,
                    read_u_32_output_tmp_40cd9_108,
                    read_u_32_output_tmp_40cd9_119,
                    read_u_32_output_tmp_40cd9_130,
                    UInt32_1779033703,
                    UInt32_3144134277,
                    UInt32_1013904242,
                    UInt32_2773480762,
                    PackedUInt32::from_limbs([
                        ((xor_col88) + ((xor_col89) * (M31_256))),
                        ((xor_col90) + ((xor_col91) * (M31_256))),
                    ]),
                    UInt32_2600822924,
                    PackedUInt32::from_limbs([
                        (((decode_blake_opcode_output_tmp_40cd9_42.2[1].as_m31()) * (M31_9812))
                            + (((M31_1)
                                - (decode_blake_opcode_output_tmp_40cd9_42.2[1].as_m31()))
                                * (M31_55723))),
                        (((decode_blake_opcode_output_tmp_40cd9_42.2[1].as_m31()) * (M31_57468))
                            + (((M31_1)
                                - (decode_blake_opcode_output_tmp_40cd9_42.2[1].as_m31()))
                                * (M31_8067))),
                    ]),
                    UInt32_1541459225,
                ];

                *lookup_data.blake_round_38 = [
                    M31_40528774,
                    seq,
                    M31_0,
                    low_16_bits_col38,
                    high_16_bits_col39,
                    low_16_bits_col44,
                    high_16_bits_col45,
                    low_16_bits_col50,
                    high_16_bits_col51,
                    low_16_bits_col56,
                    high_16_bits_col57,
                    low_16_bits_col62,
                    high_16_bits_col63,
                    low_16_bits_col68,
                    high_16_bits_col69,
                    low_16_bits_col74,
                    high_16_bits_col75,
                    low_16_bits_col80,
                    high_16_bits_col81,
                    M31_58983,
                    M31_27145,
                    M31_44677,
                    M31_47975,
                    M31_62322,
                    M31_15470,
                    M31_62778,
                    M31_42319,
                    create_blake_round_input_output_tmp_40cd9_143[12]
                        .low()
                        .as_m31(),
                    create_blake_round_input_output_tmp_40cd9_143[12]
                        .high()
                        .as_m31(),
                    M31_26764,
                    M31_39685,
                    create_blake_round_input_output_tmp_40cd9_143[14]
                        .low()
                        .as_m31(),
                    create_blake_round_input_output_tmp_40cd9_143[14]
                        .high()
                        .as_m31(),
                    M31_52505,
                    M31_23520,
                    decode_blake_opcode_output_tmp_40cd9_42.0[1],
                ];
                *sub_component_inputs.blake_round[0] = (
                    seq,
                    M31_0,
                    (
                        [
                            create_blake_round_input_output_tmp_40cd9_143[0],
                            create_blake_round_input_output_tmp_40cd9_143[1],
                            create_blake_round_input_output_tmp_40cd9_143[2],
                            create_blake_round_input_output_tmp_40cd9_143[3],
                            create_blake_round_input_output_tmp_40cd9_143[4],
                            create_blake_round_input_output_tmp_40cd9_143[5],
                            create_blake_round_input_output_tmp_40cd9_143[6],
                            create_blake_round_input_output_tmp_40cd9_143[7],
                            UInt32_1779033703,
                            UInt32_3144134277,
                            UInt32_1013904242,
                            UInt32_2773480762,
                            create_blake_round_input_output_tmp_40cd9_143[12],
                            UInt32_2600822924,
                            create_blake_round_input_output_tmp_40cd9_143[14],
                            UInt32_1541459225,
                        ],
                        decode_blake_opcode_output_tmp_40cd9_42.0[1],
                    ),
                );
                let blake_round_output_round_0_tmp_40cd9_145 = blake_round_state.deduce_output((
                    seq,
                    M31_0,
                    (
                        [
                            create_blake_round_input_output_tmp_40cd9_143[0],
                            create_blake_round_input_output_tmp_40cd9_143[1],
                            create_blake_round_input_output_tmp_40cd9_143[2],
                            create_blake_round_input_output_tmp_40cd9_143[3],
                            create_blake_round_input_output_tmp_40cd9_143[4],
                            create_blake_round_input_output_tmp_40cd9_143[5],
                            create_blake_round_input_output_tmp_40cd9_143[6],
                            create_blake_round_input_output_tmp_40cd9_143[7],
                            UInt32_1779033703,
                            UInt32_3144134277,
                            UInt32_1013904242,
                            UInt32_2773480762,
                            create_blake_round_input_output_tmp_40cd9_143[12],
                            UInt32_2600822924,
                            create_blake_round_input_output_tmp_40cd9_143[14],
                            UInt32_1541459225,
                        ],
                        decode_blake_opcode_output_tmp_40cd9_42.0[1],
                    ),
                ));
                *sub_component_inputs.blake_round[1] = (
                    seq,
                    M31_1,
                    (
                        [
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[0],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[1],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[2],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[3],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[4],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[5],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[6],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[7],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[8],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[9],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[10],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[11],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[12],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[13],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[14],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[15],
                        ],
                        blake_round_output_round_0_tmp_40cd9_145.2 .1,
                    ),
                );
                let blake_round_output_round_1_tmp_40cd9_146 = blake_round_state.deduce_output((
                    seq,
                    M31_1,
                    (
                        [
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[0],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[1],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[2],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[3],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[4],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[5],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[6],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[7],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[8],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[9],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[10],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[11],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[12],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[13],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[14],
                            blake_round_output_round_0_tmp_40cd9_145.2 .0[15],
                        ],
                        blake_round_output_round_0_tmp_40cd9_145.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[2] = (
                    seq,
                    M31_2,
                    (
                        [
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[0],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[1],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[2],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[3],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[4],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[5],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[6],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[7],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[8],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[9],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[10],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[11],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[12],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[13],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[14],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[15],
                        ],
                        blake_round_output_round_1_tmp_40cd9_146.2 .1,
                    ),
                );
                let blake_round_output_round_2_tmp_40cd9_147 = blake_round_state.deduce_output((
                    seq,
                    M31_2,
                    (
                        [
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[0],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[1],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[2],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[3],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[4],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[5],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[6],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[7],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[8],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[9],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[10],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[11],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[12],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[13],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[14],
                            blake_round_output_round_1_tmp_40cd9_146.2 .0[15],
                        ],
                        blake_round_output_round_1_tmp_40cd9_146.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[3] = (
                    seq,
                    M31_3,
                    (
                        [
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[0],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[1],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[2],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[3],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[4],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[5],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[6],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[7],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[8],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[9],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[10],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[11],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[12],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[13],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[14],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[15],
                        ],
                        blake_round_output_round_2_tmp_40cd9_147.2 .1,
                    ),
                );
                let blake_round_output_round_3_tmp_40cd9_148 = blake_round_state.deduce_output((
                    seq,
                    M31_3,
                    (
                        [
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[0],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[1],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[2],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[3],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[4],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[5],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[6],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[7],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[8],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[9],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[10],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[11],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[12],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[13],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[14],
                            blake_round_output_round_2_tmp_40cd9_147.2 .0[15],
                        ],
                        blake_round_output_round_2_tmp_40cd9_147.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[4] = (
                    seq,
                    M31_4,
                    (
                        [
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[0],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[1],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[2],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[3],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[4],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[5],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[6],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[7],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[8],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[9],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[10],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[11],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[12],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[13],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[14],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[15],
                        ],
                        blake_round_output_round_3_tmp_40cd9_148.2 .1,
                    ),
                );
                let blake_round_output_round_4_tmp_40cd9_149 = blake_round_state.deduce_output((
                    seq,
                    M31_4,
                    (
                        [
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[0],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[1],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[2],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[3],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[4],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[5],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[6],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[7],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[8],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[9],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[10],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[11],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[12],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[13],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[14],
                            blake_round_output_round_3_tmp_40cd9_148.2 .0[15],
                        ],
                        blake_round_output_round_3_tmp_40cd9_148.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[5] = (
                    seq,
                    M31_5,
                    (
                        [
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[0],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[1],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[2],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[3],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[4],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[5],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[6],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[7],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[8],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[9],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[10],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[11],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[12],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[13],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[14],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[15],
                        ],
                        blake_round_output_round_4_tmp_40cd9_149.2 .1,
                    ),
                );
                let blake_round_output_round_5_tmp_40cd9_150 = blake_round_state.deduce_output((
                    seq,
                    M31_5,
                    (
                        [
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[0],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[1],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[2],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[3],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[4],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[5],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[6],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[7],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[8],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[9],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[10],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[11],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[12],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[13],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[14],
                            blake_round_output_round_4_tmp_40cd9_149.2 .0[15],
                        ],
                        blake_round_output_round_4_tmp_40cd9_149.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[6] = (
                    seq,
                    M31_6,
                    (
                        [
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[0],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[1],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[2],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[3],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[4],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[5],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[6],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[7],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[8],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[9],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[10],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[11],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[12],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[13],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[14],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[15],
                        ],
                        blake_round_output_round_5_tmp_40cd9_150.2 .1,
                    ),
                );
                let blake_round_output_round_6_tmp_40cd9_151 = blake_round_state.deduce_output((
                    seq,
                    M31_6,
                    (
                        [
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[0],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[1],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[2],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[3],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[4],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[5],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[6],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[7],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[8],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[9],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[10],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[11],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[12],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[13],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[14],
                            blake_round_output_round_5_tmp_40cd9_150.2 .0[15],
                        ],
                        blake_round_output_round_5_tmp_40cd9_150.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[7] = (
                    seq,
                    M31_7,
                    (
                        [
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[0],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[1],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[2],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[3],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[4],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[5],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[6],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[7],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[8],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[9],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[10],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[11],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[12],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[13],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[14],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[15],
                        ],
                        blake_round_output_round_6_tmp_40cd9_151.2 .1,
                    ),
                );
                let blake_round_output_round_7_tmp_40cd9_152 = blake_round_state.deduce_output((
                    seq,
                    M31_7,
                    (
                        [
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[0],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[1],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[2],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[3],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[4],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[5],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[6],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[7],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[8],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[9],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[10],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[11],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[12],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[13],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[14],
                            blake_round_output_round_6_tmp_40cd9_151.2 .0[15],
                        ],
                        blake_round_output_round_6_tmp_40cd9_151.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[8] = (
                    seq,
                    M31_8,
                    (
                        [
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[0],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[1],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[2],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[3],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[4],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[5],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[6],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[7],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[8],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[9],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[10],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[11],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[12],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[13],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[14],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[15],
                        ],
                        blake_round_output_round_7_tmp_40cd9_152.2 .1,
                    ),
                );
                let blake_round_output_round_8_tmp_40cd9_153 = blake_round_state.deduce_output((
                    seq,
                    M31_8,
                    (
                        [
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[0],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[1],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[2],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[3],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[4],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[5],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[6],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[7],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[8],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[9],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[10],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[11],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[12],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[13],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[14],
                            blake_round_output_round_7_tmp_40cd9_152.2 .0[15],
                        ],
                        blake_round_output_round_7_tmp_40cd9_152.2 .1,
                    ),
                ));
                *sub_component_inputs.blake_round[9] = (
                    seq,
                    M31_9,
                    (
                        [
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[0],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[1],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[2],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[3],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[4],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[5],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[6],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[7],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[8],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[9],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[10],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[11],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[12],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[13],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[14],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[15],
                        ],
                        blake_round_output_round_8_tmp_40cd9_153.2 .1,
                    ),
                );
                let blake_round_output_round_9_tmp_40cd9_154 = blake_round_state.deduce_output((
                    seq,
                    M31_9,
                    (
                        [
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[0],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[1],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[2],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[3],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[4],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[5],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[6],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[7],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[8],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[9],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[10],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[11],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[12],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[13],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[14],
                            blake_round_output_round_8_tmp_40cd9_153.2 .0[15],
                        ],
                        blake_round_output_round_8_tmp_40cd9_153.2 .1,
                    ),
                ));
                let blake_round_output_limb_0_col92 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [0]
                .low()
                .as_m31();
                *row[92] = blake_round_output_limb_0_col92;
                let blake_round_output_limb_1_col93 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [0]
                .high()
                .as_m31();
                *row[93] = blake_round_output_limb_1_col93;
                let blake_round_output_limb_2_col94 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [1]
                .low()
                .as_m31();
                *row[94] = blake_round_output_limb_2_col94;
                let blake_round_output_limb_3_col95 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [1]
                .high()
                .as_m31();
                *row[95] = blake_round_output_limb_3_col95;
                let blake_round_output_limb_4_col96 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [2]
                .low()
                .as_m31();
                *row[96] = blake_round_output_limb_4_col96;
                let blake_round_output_limb_5_col97 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [2]
                .high()
                .as_m31();
                *row[97] = blake_round_output_limb_5_col97;
                let blake_round_output_limb_6_col98 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [3]
                .low()
                .as_m31();
                *row[98] = blake_round_output_limb_6_col98;
                let blake_round_output_limb_7_col99 = blake_round_output_round_9_tmp_40cd9_154.2 .0
                    [3]
                .high()
                .as_m31();
                *row[99] = blake_round_output_limb_7_col99;
                let blake_round_output_limb_8_col100 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[4]
                        .low()
                        .as_m31();
                *row[100] = blake_round_output_limb_8_col100;
                let blake_round_output_limb_9_col101 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[4]
                        .high()
                        .as_m31();
                *row[101] = blake_round_output_limb_9_col101;
                let blake_round_output_limb_10_col102 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[5]
                        .low()
                        .as_m31();
                *row[102] = blake_round_output_limb_10_col102;
                let blake_round_output_limb_11_col103 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[5]
                        .high()
                        .as_m31();
                *row[103] = blake_round_output_limb_11_col103;
                let blake_round_output_limb_12_col104 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[6]
                        .low()
                        .as_m31();
                *row[104] = blake_round_output_limb_12_col104;
                let blake_round_output_limb_13_col105 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[6]
                        .high()
                        .as_m31();
                *row[105] = blake_round_output_limb_13_col105;
                let blake_round_output_limb_14_col106 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[7]
                        .low()
                        .as_m31();
                *row[106] = blake_round_output_limb_14_col106;
                let blake_round_output_limb_15_col107 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[7]
                        .high()
                        .as_m31();
                *row[107] = blake_round_output_limb_15_col107;
                let blake_round_output_limb_16_col108 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[8]
                        .low()
                        .as_m31();
                *row[108] = blake_round_output_limb_16_col108;
                let blake_round_output_limb_17_col109 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[8]
                        .high()
                        .as_m31();
                *row[109] = blake_round_output_limb_17_col109;
                let blake_round_output_limb_18_col110 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[9]
                        .low()
                        .as_m31();
                *row[110] = blake_round_output_limb_18_col110;
                let blake_round_output_limb_19_col111 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[9]
                        .high()
                        .as_m31();
                *row[111] = blake_round_output_limb_19_col111;
                let blake_round_output_limb_20_col112 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[10]
                        .low()
                        .as_m31();
                *row[112] = blake_round_output_limb_20_col112;
                let blake_round_output_limb_21_col113 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[10]
                        .high()
                        .as_m31();
                *row[113] = blake_round_output_limb_21_col113;
                let blake_round_output_limb_22_col114 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[11]
                        .low()
                        .as_m31();
                *row[114] = blake_round_output_limb_22_col114;
                let blake_round_output_limb_23_col115 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[11]
                        .high()
                        .as_m31();
                *row[115] = blake_round_output_limb_23_col115;
                let blake_round_output_limb_24_col116 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[12]
                        .low()
                        .as_m31();
                *row[116] = blake_round_output_limb_24_col116;
                let blake_round_output_limb_25_col117 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[12]
                        .high()
                        .as_m31();
                *row[117] = blake_round_output_limb_25_col117;
                let blake_round_output_limb_26_col118 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[13]
                        .low()
                        .as_m31();
                *row[118] = blake_round_output_limb_26_col118;
                let blake_round_output_limb_27_col119 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[13]
                        .high()
                        .as_m31();
                *row[119] = blake_round_output_limb_27_col119;
                let blake_round_output_limb_28_col120 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[14]
                        .low()
                        .as_m31();
                *row[120] = blake_round_output_limb_28_col120;
                let blake_round_output_limb_29_col121 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[14]
                        .high()
                        .as_m31();
                *row[121] = blake_round_output_limb_29_col121;
                let blake_round_output_limb_30_col122 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[15]
                        .low()
                        .as_m31();
                *row[122] = blake_round_output_limb_30_col122;
                let blake_round_output_limb_31_col123 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[15]
                        .high()
                        .as_m31();
                *row[123] = blake_round_output_limb_31_col123;
                let blake_round_output_limb_32_col124 =
                    blake_round_output_round_9_tmp_40cd9_154.2 .1;
                *row[124] = blake_round_output_limb_32_col124;
                *lookup_data.blake_round_39 = [
                    M31_40528774,
                    seq,
                    M31_10,
                    blake_round_output_limb_0_col92,
                    blake_round_output_limb_1_col93,
                    blake_round_output_limb_2_col94,
                    blake_round_output_limb_3_col95,
                    blake_round_output_limb_4_col96,
                    blake_round_output_limb_5_col97,
                    blake_round_output_limb_6_col98,
                    blake_round_output_limb_7_col99,
                    blake_round_output_limb_8_col100,
                    blake_round_output_limb_9_col101,
                    blake_round_output_limb_10_col102,
                    blake_round_output_limb_11_col103,
                    blake_round_output_limb_12_col104,
                    blake_round_output_limb_13_col105,
                    blake_round_output_limb_14_col106,
                    blake_round_output_limb_15_col107,
                    blake_round_output_limb_16_col108,
                    blake_round_output_limb_17_col109,
                    blake_round_output_limb_18_col110,
                    blake_round_output_limb_19_col111,
                    blake_round_output_limb_20_col112,
                    blake_round_output_limb_21_col113,
                    blake_round_output_limb_22_col114,
                    blake_round_output_limb_23_col115,
                    blake_round_output_limb_24_col116,
                    blake_round_output_limb_25_col117,
                    blake_round_output_limb_26_col118,
                    blake_round_output_limb_27_col119,
                    blake_round_output_limb_28_col120,
                    blake_round_output_limb_29_col121,
                    blake_round_output_limb_30_col122,
                    blake_round_output_limb_31_col123,
                    blake_round_output_limb_32_col124,
                ];

                // Create Blake Output.

                *sub_component_inputs.triple_xor_32[0] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[0],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[8],
                    create_blake_round_input_output_tmp_40cd9_143[0],
                ];
                let triple_xor_32_output_tmp_40cd9_155 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[0],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[8],
                    create_blake_round_input_output_tmp_40cd9_143[0],
                ]);
                let triple_xor_32_output_limb_0_col125 =
                    triple_xor_32_output_tmp_40cd9_155.low().as_m31();
                *row[125] = triple_xor_32_output_limb_0_col125;
                let triple_xor_32_output_limb_1_col126 =
                    triple_xor_32_output_tmp_40cd9_155.high().as_m31();
                *row[126] = triple_xor_32_output_limb_1_col126;
                *lookup_data.triple_xor_32_40 = [
                    M31_990559919,
                    blake_round_output_limb_0_col92,
                    blake_round_output_limb_1_col93,
                    blake_round_output_limb_16_col108,
                    blake_round_output_limb_17_col109,
                    low_16_bits_col38,
                    high_16_bits_col39,
                    triple_xor_32_output_limb_0_col125,
                    triple_xor_32_output_limb_1_col126,
                ];
                *sub_component_inputs.triple_xor_32[1] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[1],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[9],
                    create_blake_round_input_output_tmp_40cd9_143[1],
                ];
                let triple_xor_32_output_tmp_40cd9_156 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[1],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[9],
                    create_blake_round_input_output_tmp_40cd9_143[1],
                ]);
                let triple_xor_32_output_limb_0_col127 =
                    triple_xor_32_output_tmp_40cd9_156.low().as_m31();
                *row[127] = triple_xor_32_output_limb_0_col127;
                let triple_xor_32_output_limb_1_col128 =
                    triple_xor_32_output_tmp_40cd9_156.high().as_m31();
                *row[128] = triple_xor_32_output_limb_1_col128;
                *lookup_data.triple_xor_32_41 = [
                    M31_990559919,
                    blake_round_output_limb_2_col94,
                    blake_round_output_limb_3_col95,
                    blake_round_output_limb_18_col110,
                    blake_round_output_limb_19_col111,
                    low_16_bits_col44,
                    high_16_bits_col45,
                    triple_xor_32_output_limb_0_col127,
                    triple_xor_32_output_limb_1_col128,
                ];
                *sub_component_inputs.triple_xor_32[2] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[2],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[10],
                    create_blake_round_input_output_tmp_40cd9_143[2],
                ];
                let triple_xor_32_output_tmp_40cd9_157 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[2],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[10],
                    create_blake_round_input_output_tmp_40cd9_143[2],
                ]);
                let triple_xor_32_output_limb_0_col129 =
                    triple_xor_32_output_tmp_40cd9_157.low().as_m31();
                *row[129] = triple_xor_32_output_limb_0_col129;
                let triple_xor_32_output_limb_1_col130 =
                    triple_xor_32_output_tmp_40cd9_157.high().as_m31();
                *row[130] = triple_xor_32_output_limb_1_col130;
                *lookup_data.triple_xor_32_42 = [
                    M31_990559919,
                    blake_round_output_limb_4_col96,
                    blake_round_output_limb_5_col97,
                    blake_round_output_limb_20_col112,
                    blake_round_output_limb_21_col113,
                    low_16_bits_col50,
                    high_16_bits_col51,
                    triple_xor_32_output_limb_0_col129,
                    triple_xor_32_output_limb_1_col130,
                ];
                *sub_component_inputs.triple_xor_32[3] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[3],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[11],
                    create_blake_round_input_output_tmp_40cd9_143[3],
                ];
                let triple_xor_32_output_tmp_40cd9_158 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[3],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[11],
                    create_blake_round_input_output_tmp_40cd9_143[3],
                ]);
                let triple_xor_32_output_limb_0_col131 =
                    triple_xor_32_output_tmp_40cd9_158.low().as_m31();
                *row[131] = triple_xor_32_output_limb_0_col131;
                let triple_xor_32_output_limb_1_col132 =
                    triple_xor_32_output_tmp_40cd9_158.high().as_m31();
                *row[132] = triple_xor_32_output_limb_1_col132;
                *lookup_data.triple_xor_32_43 = [
                    M31_990559919,
                    blake_round_output_limb_6_col98,
                    blake_round_output_limb_7_col99,
                    blake_round_output_limb_22_col114,
                    blake_round_output_limb_23_col115,
                    low_16_bits_col56,
                    high_16_bits_col57,
                    triple_xor_32_output_limb_0_col131,
                    triple_xor_32_output_limb_1_col132,
                ];
                *sub_component_inputs.triple_xor_32[4] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[4],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[12],
                    create_blake_round_input_output_tmp_40cd9_143[4],
                ];
                let triple_xor_32_output_tmp_40cd9_159 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[4],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[12],
                    create_blake_round_input_output_tmp_40cd9_143[4],
                ]);
                let triple_xor_32_output_limb_0_col133 =
                    triple_xor_32_output_tmp_40cd9_159.low().as_m31();
                *row[133] = triple_xor_32_output_limb_0_col133;
                let triple_xor_32_output_limb_1_col134 =
                    triple_xor_32_output_tmp_40cd9_159.high().as_m31();
                *row[134] = triple_xor_32_output_limb_1_col134;
                *lookup_data.triple_xor_32_44 = [
                    M31_990559919,
                    blake_round_output_limb_8_col100,
                    blake_round_output_limb_9_col101,
                    blake_round_output_limb_24_col116,
                    blake_round_output_limb_25_col117,
                    low_16_bits_col62,
                    high_16_bits_col63,
                    triple_xor_32_output_limb_0_col133,
                    triple_xor_32_output_limb_1_col134,
                ];
                *sub_component_inputs.triple_xor_32[5] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[5],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[13],
                    create_blake_round_input_output_tmp_40cd9_143[5],
                ];
                let triple_xor_32_output_tmp_40cd9_160 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[5],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[13],
                    create_blake_round_input_output_tmp_40cd9_143[5],
                ]);
                let triple_xor_32_output_limb_0_col135 =
                    triple_xor_32_output_tmp_40cd9_160.low().as_m31();
                *row[135] = triple_xor_32_output_limb_0_col135;
                let triple_xor_32_output_limb_1_col136 =
                    triple_xor_32_output_tmp_40cd9_160.high().as_m31();
                *row[136] = triple_xor_32_output_limb_1_col136;
                *lookup_data.triple_xor_32_45 = [
                    M31_990559919,
                    blake_round_output_limb_10_col102,
                    blake_round_output_limb_11_col103,
                    blake_round_output_limb_26_col118,
                    blake_round_output_limb_27_col119,
                    low_16_bits_col68,
                    high_16_bits_col69,
                    triple_xor_32_output_limb_0_col135,
                    triple_xor_32_output_limb_1_col136,
                ];
                *sub_component_inputs.triple_xor_32[6] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[6],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[14],
                    create_blake_round_input_output_tmp_40cd9_143[6],
                ];
                let triple_xor_32_output_tmp_40cd9_161 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[6],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[14],
                    create_blake_round_input_output_tmp_40cd9_143[6],
                ]);
                let triple_xor_32_output_limb_0_col137 =
                    triple_xor_32_output_tmp_40cd9_161.low().as_m31();
                *row[137] = triple_xor_32_output_limb_0_col137;
                let triple_xor_32_output_limb_1_col138 =
                    triple_xor_32_output_tmp_40cd9_161.high().as_m31();
                *row[138] = triple_xor_32_output_limb_1_col138;
                *lookup_data.triple_xor_32_46 = [
                    M31_990559919,
                    blake_round_output_limb_12_col104,
                    blake_round_output_limb_13_col105,
                    blake_round_output_limb_28_col120,
                    blake_round_output_limb_29_col121,
                    low_16_bits_col74,
                    high_16_bits_col75,
                    triple_xor_32_output_limb_0_col137,
                    triple_xor_32_output_limb_1_col138,
                ];
                *sub_component_inputs.triple_xor_32[7] = [
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[7],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[15],
                    create_blake_round_input_output_tmp_40cd9_143[7],
                ];
                let triple_xor_32_output_tmp_40cd9_162 = PackedTripleXor32::deduce_output([
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[7],
                    blake_round_output_round_9_tmp_40cd9_154.2 .0[15],
                    create_blake_round_input_output_tmp_40cd9_143[7],
                ]);
                let triple_xor_32_output_limb_0_col139 =
                    triple_xor_32_output_tmp_40cd9_162.low().as_m31();
                *row[139] = triple_xor_32_output_limb_0_col139;
                let triple_xor_32_output_limb_1_col140 =
                    triple_xor_32_output_tmp_40cd9_162.high().as_m31();
                *row[140] = triple_xor_32_output_limb_1_col140;
                *lookup_data.triple_xor_32_47 = [
                    M31_990559919,
                    blake_round_output_limb_14_col106,
                    blake_round_output_limb_15_col107,
                    blake_round_output_limb_30_col122,
                    blake_round_output_limb_31_col123,
                    low_16_bits_col80,
                    high_16_bits_col81,
                    triple_xor_32_output_limb_0_col139,
                    triple_xor_32_output_limb_1_col140,
                ];
                let create_blake_output_output_tmp_40cd9_163 = [
                    triple_xor_32_output_tmp_40cd9_155,
                    triple_xor_32_output_tmp_40cd9_156,
                    triple_xor_32_output_tmp_40cd9_157,
                    triple_xor_32_output_tmp_40cd9_158,
                    triple_xor_32_output_tmp_40cd9_159,
                    triple_xor_32_output_tmp_40cd9_160,
                    triple_xor_32_output_tmp_40cd9_161,
                    triple_xor_32_output_tmp_40cd9_162,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_164 =
                    ((create_blake_output_output_tmp_40cd9_163[0].low()) >> (UInt16_9));
                let low_7_ms_bits_col141 = low_7_ms_bits_tmp_40cd9_164.as_m31();
                *row[141] = low_7_ms_bits_col141;
                let high_14_ms_bits_tmp_40cd9_165 =
                    ((create_blake_output_output_tmp_40cd9_163[0].high()) >> (UInt16_2));
                let high_14_ms_bits_col142 = high_14_ms_bits_tmp_40cd9_165.as_m31();
                *row[142] = high_14_ms_bits_col142;
                let high_2_ls_bits_tmp_40cd9_166 =
                    ((triple_xor_32_output_limb_1_col126) - ((high_14_ms_bits_col142) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_167 = ((high_14_ms_bits_tmp_40cd9_165) >> (UInt16_9));
                let high_5_ms_bits_col143 = high_5_ms_bits_tmp_40cd9_167.as_m31();
                *row[143] = high_5_ms_bits_col143;
                *sub_component_inputs.range_check_7_2_5[9] = [
                    low_7_ms_bits_col141,
                    high_2_ls_bits_tmp_40cd9_166,
                    high_5_ms_bits_col143,
                ];
                *lookup_data.range_check_7_2_5_48 = [
                    M31_371240602,
                    low_7_ms_bits_col141,
                    high_2_ls_bits_tmp_40cd9_166,
                    high_5_ms_bits_col143,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_168 = memory_address_to_id_state
                    .deduce_output(decode_blake_opcode_output_tmp_40cd9_42.0[2]);
                let new_state_0_id_col144 = memory_address_to_id_value_tmp_40cd9_168;
                *row[144] = new_state_0_id_col144;
                *sub_component_inputs.memory_address_to_id[12] =
                    decode_blake_opcode_output_tmp_40cd9_42.0[2];
                *lookup_data.memory_address_to_id_49 = [
                    M31_1444891767,
                    decode_blake_opcode_output_tmp_40cd9_42.0[2],
                    new_state_0_id_col144,
                ];

                *sub_component_inputs.memory_id_to_big[12] = new_state_0_id_col144;
                *lookup_data.memory_id_to_big_50 = [
                    M31_1662111297,
                    new_state_0_id_col144,
                    ((triple_xor_32_output_limb_0_col125) - ((low_7_ms_bits_col141) * (M31_512))),
                    ((low_7_ms_bits_col141) + ((high_2_ls_bits_tmp_40cd9_166) * (M31_128))),
                    ((high_14_ms_bits_col142) - ((high_5_ms_bits_col143) * (M31_512))),
                    high_5_ms_bits_col143,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_170 =
                    ((create_blake_output_output_tmp_40cd9_163[1].low()) >> (UInt16_9));
                let low_7_ms_bits_col145 = low_7_ms_bits_tmp_40cd9_170.as_m31();
                *row[145] = low_7_ms_bits_col145;
                let high_14_ms_bits_tmp_40cd9_171 =
                    ((create_blake_output_output_tmp_40cd9_163[1].high()) >> (UInt16_2));
                let high_14_ms_bits_col146 = high_14_ms_bits_tmp_40cd9_171.as_m31();
                *row[146] = high_14_ms_bits_col146;
                let high_2_ls_bits_tmp_40cd9_172 =
                    ((triple_xor_32_output_limb_1_col128) - ((high_14_ms_bits_col146) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_173 = ((high_14_ms_bits_tmp_40cd9_171) >> (UInt16_9));
                let high_5_ms_bits_col147 = high_5_ms_bits_tmp_40cd9_173.as_m31();
                *row[147] = high_5_ms_bits_col147;
                *sub_component_inputs.range_check_7_2_5[10] = [
                    low_7_ms_bits_col145,
                    high_2_ls_bits_tmp_40cd9_172,
                    high_5_ms_bits_col147,
                ];
                *lookup_data.range_check_7_2_5_51 = [
                    M31_371240602,
                    low_7_ms_bits_col145,
                    high_2_ls_bits_tmp_40cd9_172,
                    high_5_ms_bits_col147,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_174 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_1)));
                let new_state_1_id_col148 = memory_address_to_id_value_tmp_40cd9_174;
                *row[148] = new_state_1_id_col148;
                *sub_component_inputs.memory_address_to_id[13] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_1));
                *lookup_data.memory_address_to_id_52 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_1)),
                    new_state_1_id_col148,
                ];

                *sub_component_inputs.memory_id_to_big[13] = new_state_1_id_col148;
                *lookup_data.memory_id_to_big_53 = [
                    M31_1662111297,
                    new_state_1_id_col148,
                    ((triple_xor_32_output_limb_0_col127) - ((low_7_ms_bits_col145) * (M31_512))),
                    ((low_7_ms_bits_col145) + ((high_2_ls_bits_tmp_40cd9_172) * (M31_128))),
                    ((high_14_ms_bits_col146) - ((high_5_ms_bits_col147) * (M31_512))),
                    high_5_ms_bits_col147,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_176 =
                    ((create_blake_output_output_tmp_40cd9_163[2].low()) >> (UInt16_9));
                let low_7_ms_bits_col149 = low_7_ms_bits_tmp_40cd9_176.as_m31();
                *row[149] = low_7_ms_bits_col149;
                let high_14_ms_bits_tmp_40cd9_177 =
                    ((create_blake_output_output_tmp_40cd9_163[2].high()) >> (UInt16_2));
                let high_14_ms_bits_col150 = high_14_ms_bits_tmp_40cd9_177.as_m31();
                *row[150] = high_14_ms_bits_col150;
                let high_2_ls_bits_tmp_40cd9_178 =
                    ((triple_xor_32_output_limb_1_col130) - ((high_14_ms_bits_col150) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_179 = ((high_14_ms_bits_tmp_40cd9_177) >> (UInt16_9));
                let high_5_ms_bits_col151 = high_5_ms_bits_tmp_40cd9_179.as_m31();
                *row[151] = high_5_ms_bits_col151;
                *sub_component_inputs.range_check_7_2_5[11] = [
                    low_7_ms_bits_col149,
                    high_2_ls_bits_tmp_40cd9_178,
                    high_5_ms_bits_col151,
                ];
                *lookup_data.range_check_7_2_5_54 = [
                    M31_371240602,
                    low_7_ms_bits_col149,
                    high_2_ls_bits_tmp_40cd9_178,
                    high_5_ms_bits_col151,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_180 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_2)));
                let new_state_2_id_col152 = memory_address_to_id_value_tmp_40cd9_180;
                *row[152] = new_state_2_id_col152;
                *sub_component_inputs.memory_address_to_id[14] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_2));
                *lookup_data.memory_address_to_id_55 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_2)),
                    new_state_2_id_col152,
                ];

                *sub_component_inputs.memory_id_to_big[14] = new_state_2_id_col152;
                *lookup_data.memory_id_to_big_56 = [
                    M31_1662111297,
                    new_state_2_id_col152,
                    ((triple_xor_32_output_limb_0_col129) - ((low_7_ms_bits_col149) * (M31_512))),
                    ((low_7_ms_bits_col149) + ((high_2_ls_bits_tmp_40cd9_178) * (M31_128))),
                    ((high_14_ms_bits_col150) - ((high_5_ms_bits_col151) * (M31_512))),
                    high_5_ms_bits_col151,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_182 =
                    ((create_blake_output_output_tmp_40cd9_163[3].low()) >> (UInt16_9));
                let low_7_ms_bits_col153 = low_7_ms_bits_tmp_40cd9_182.as_m31();
                *row[153] = low_7_ms_bits_col153;
                let high_14_ms_bits_tmp_40cd9_183 =
                    ((create_blake_output_output_tmp_40cd9_163[3].high()) >> (UInt16_2));
                let high_14_ms_bits_col154 = high_14_ms_bits_tmp_40cd9_183.as_m31();
                *row[154] = high_14_ms_bits_col154;
                let high_2_ls_bits_tmp_40cd9_184 =
                    ((triple_xor_32_output_limb_1_col132) - ((high_14_ms_bits_col154) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_185 = ((high_14_ms_bits_tmp_40cd9_183) >> (UInt16_9));
                let high_5_ms_bits_col155 = high_5_ms_bits_tmp_40cd9_185.as_m31();
                *row[155] = high_5_ms_bits_col155;
                *sub_component_inputs.range_check_7_2_5[12] = [
                    low_7_ms_bits_col153,
                    high_2_ls_bits_tmp_40cd9_184,
                    high_5_ms_bits_col155,
                ];
                *lookup_data.range_check_7_2_5_57 = [
                    M31_371240602,
                    low_7_ms_bits_col153,
                    high_2_ls_bits_tmp_40cd9_184,
                    high_5_ms_bits_col155,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_186 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_3)));
                let new_state_3_id_col156 = memory_address_to_id_value_tmp_40cd9_186;
                *row[156] = new_state_3_id_col156;
                *sub_component_inputs.memory_address_to_id[15] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_3));
                *lookup_data.memory_address_to_id_58 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_3)),
                    new_state_3_id_col156,
                ];

                *sub_component_inputs.memory_id_to_big[15] = new_state_3_id_col156;
                *lookup_data.memory_id_to_big_59 = [
                    M31_1662111297,
                    new_state_3_id_col156,
                    ((triple_xor_32_output_limb_0_col131) - ((low_7_ms_bits_col153) * (M31_512))),
                    ((low_7_ms_bits_col153) + ((high_2_ls_bits_tmp_40cd9_184) * (M31_128))),
                    ((high_14_ms_bits_col154) - ((high_5_ms_bits_col155) * (M31_512))),
                    high_5_ms_bits_col155,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_188 =
                    ((create_blake_output_output_tmp_40cd9_163[4].low()) >> (UInt16_9));
                let low_7_ms_bits_col157 = low_7_ms_bits_tmp_40cd9_188.as_m31();
                *row[157] = low_7_ms_bits_col157;
                let high_14_ms_bits_tmp_40cd9_189 =
                    ((create_blake_output_output_tmp_40cd9_163[4].high()) >> (UInt16_2));
                let high_14_ms_bits_col158 = high_14_ms_bits_tmp_40cd9_189.as_m31();
                *row[158] = high_14_ms_bits_col158;
                let high_2_ls_bits_tmp_40cd9_190 =
                    ((triple_xor_32_output_limb_1_col134) - ((high_14_ms_bits_col158) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_191 = ((high_14_ms_bits_tmp_40cd9_189) >> (UInt16_9));
                let high_5_ms_bits_col159 = high_5_ms_bits_tmp_40cd9_191.as_m31();
                *row[159] = high_5_ms_bits_col159;
                *sub_component_inputs.range_check_7_2_5[13] = [
                    low_7_ms_bits_col157,
                    high_2_ls_bits_tmp_40cd9_190,
                    high_5_ms_bits_col159,
                ];
                *lookup_data.range_check_7_2_5_60 = [
                    M31_371240602,
                    low_7_ms_bits_col157,
                    high_2_ls_bits_tmp_40cd9_190,
                    high_5_ms_bits_col159,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_192 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_4)));
                let new_state_4_id_col160 = memory_address_to_id_value_tmp_40cd9_192;
                *row[160] = new_state_4_id_col160;
                *sub_component_inputs.memory_address_to_id[16] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_4));
                *lookup_data.memory_address_to_id_61 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_4)),
                    new_state_4_id_col160,
                ];

                *sub_component_inputs.memory_id_to_big[16] = new_state_4_id_col160;
                *lookup_data.memory_id_to_big_62 = [
                    M31_1662111297,
                    new_state_4_id_col160,
                    ((triple_xor_32_output_limb_0_col133) - ((low_7_ms_bits_col157) * (M31_512))),
                    ((low_7_ms_bits_col157) + ((high_2_ls_bits_tmp_40cd9_190) * (M31_128))),
                    ((high_14_ms_bits_col158) - ((high_5_ms_bits_col159) * (M31_512))),
                    high_5_ms_bits_col159,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_194 =
                    ((create_blake_output_output_tmp_40cd9_163[5].low()) >> (UInt16_9));
                let low_7_ms_bits_col161 = low_7_ms_bits_tmp_40cd9_194.as_m31();
                *row[161] = low_7_ms_bits_col161;
                let high_14_ms_bits_tmp_40cd9_195 =
                    ((create_blake_output_output_tmp_40cd9_163[5].high()) >> (UInt16_2));
                let high_14_ms_bits_col162 = high_14_ms_bits_tmp_40cd9_195.as_m31();
                *row[162] = high_14_ms_bits_col162;
                let high_2_ls_bits_tmp_40cd9_196 =
                    ((triple_xor_32_output_limb_1_col136) - ((high_14_ms_bits_col162) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_197 = ((high_14_ms_bits_tmp_40cd9_195) >> (UInt16_9));
                let high_5_ms_bits_col163 = high_5_ms_bits_tmp_40cd9_197.as_m31();
                *row[163] = high_5_ms_bits_col163;
                *sub_component_inputs.range_check_7_2_5[14] = [
                    low_7_ms_bits_col161,
                    high_2_ls_bits_tmp_40cd9_196,
                    high_5_ms_bits_col163,
                ];
                *lookup_data.range_check_7_2_5_63 = [
                    M31_371240602,
                    low_7_ms_bits_col161,
                    high_2_ls_bits_tmp_40cd9_196,
                    high_5_ms_bits_col163,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_198 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_5)));
                let new_state_5_id_col164 = memory_address_to_id_value_tmp_40cd9_198;
                *row[164] = new_state_5_id_col164;
                *sub_component_inputs.memory_address_to_id[17] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_5));
                *lookup_data.memory_address_to_id_64 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_5)),
                    new_state_5_id_col164,
                ];

                *sub_component_inputs.memory_id_to_big[17] = new_state_5_id_col164;
                *lookup_data.memory_id_to_big_65 = [
                    M31_1662111297,
                    new_state_5_id_col164,
                    ((triple_xor_32_output_limb_0_col135) - ((low_7_ms_bits_col161) * (M31_512))),
                    ((low_7_ms_bits_col161) + ((high_2_ls_bits_tmp_40cd9_196) * (M31_128))),
                    ((high_14_ms_bits_col162) - ((high_5_ms_bits_col163) * (M31_512))),
                    high_5_ms_bits_col163,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_200 =
                    ((create_blake_output_output_tmp_40cd9_163[6].low()) >> (UInt16_9));
                let low_7_ms_bits_col165 = low_7_ms_bits_tmp_40cd9_200.as_m31();
                *row[165] = low_7_ms_bits_col165;
                let high_14_ms_bits_tmp_40cd9_201 =
                    ((create_blake_output_output_tmp_40cd9_163[6].high()) >> (UInt16_2));
                let high_14_ms_bits_col166 = high_14_ms_bits_tmp_40cd9_201.as_m31();
                *row[166] = high_14_ms_bits_col166;
                let high_2_ls_bits_tmp_40cd9_202 =
                    ((triple_xor_32_output_limb_1_col138) - ((high_14_ms_bits_col166) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_203 = ((high_14_ms_bits_tmp_40cd9_201) >> (UInt16_9));
                let high_5_ms_bits_col167 = high_5_ms_bits_tmp_40cd9_203.as_m31();
                *row[167] = high_5_ms_bits_col167;
                *sub_component_inputs.range_check_7_2_5[15] = [
                    low_7_ms_bits_col165,
                    high_2_ls_bits_tmp_40cd9_202,
                    high_5_ms_bits_col167,
                ];
                *lookup_data.range_check_7_2_5_66 = [
                    M31_371240602,
                    low_7_ms_bits_col165,
                    high_2_ls_bits_tmp_40cd9_202,
                    high_5_ms_bits_col167,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_204 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_6)));
                let new_state_6_id_col168 = memory_address_to_id_value_tmp_40cd9_204;
                *row[168] = new_state_6_id_col168;
                *sub_component_inputs.memory_address_to_id[18] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_6));
                *lookup_data.memory_address_to_id_67 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_6)),
                    new_state_6_id_col168,
                ];

                *sub_component_inputs.memory_id_to_big[18] = new_state_6_id_col168;
                *lookup_data.memory_id_to_big_68 = [
                    M31_1662111297,
                    new_state_6_id_col168,
                    ((triple_xor_32_output_limb_0_col137) - ((low_7_ms_bits_col165) * (M31_512))),
                    ((low_7_ms_bits_col165) + ((high_2_ls_bits_tmp_40cd9_202) * (M31_128))),
                    ((high_14_ms_bits_col166) - ((high_5_ms_bits_col167) * (M31_512))),
                    high_5_ms_bits_col167,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                // Verify U 32.

                let low_7_ms_bits_tmp_40cd9_206 =
                    ((create_blake_output_output_tmp_40cd9_163[7].low()) >> (UInt16_9));
                let low_7_ms_bits_col169 = low_7_ms_bits_tmp_40cd9_206.as_m31();
                *row[169] = low_7_ms_bits_col169;
                let high_14_ms_bits_tmp_40cd9_207 =
                    ((create_blake_output_output_tmp_40cd9_163[7].high()) >> (UInt16_2));
                let high_14_ms_bits_col170 = high_14_ms_bits_tmp_40cd9_207.as_m31();
                *row[170] = high_14_ms_bits_col170;
                let high_2_ls_bits_tmp_40cd9_208 =
                    ((triple_xor_32_output_limb_1_col140) - ((high_14_ms_bits_col170) * (M31_4)));
                let high_5_ms_bits_tmp_40cd9_209 = ((high_14_ms_bits_tmp_40cd9_207) >> (UInt16_9));
                let high_5_ms_bits_col171 = high_5_ms_bits_tmp_40cd9_209.as_m31();
                *row[171] = high_5_ms_bits_col171;
                *sub_component_inputs.range_check_7_2_5[16] = [
                    low_7_ms_bits_col169,
                    high_2_ls_bits_tmp_40cd9_208,
                    high_5_ms_bits_col171,
                ];
                *lookup_data.range_check_7_2_5_69 = [
                    M31_371240602,
                    low_7_ms_bits_col169,
                    high_2_ls_bits_tmp_40cd9_208,
                    high_5_ms_bits_col171,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40cd9_210 = memory_address_to_id_state
                    .deduce_output(((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_7)));
                let new_state_7_id_col172 = memory_address_to_id_value_tmp_40cd9_210;
                *row[172] = new_state_7_id_col172;
                *sub_component_inputs.memory_address_to_id[19] =
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_7));
                *lookup_data.memory_address_to_id_70 = [
                    M31_1444891767,
                    ((decode_blake_opcode_output_tmp_40cd9_42.0[2]) + (M31_7)),
                    new_state_7_id_col172,
                ];

                *sub_component_inputs.memory_id_to_big[19] = new_state_7_id_col172;
                *lookup_data.memory_id_to_big_71 = [
                    M31_1662111297,
                    new_state_7_id_col172,
                    ((triple_xor_32_output_limb_0_col139) - ((low_7_ms_bits_col169) * (M31_512))),
                    ((low_7_ms_bits_col169) + ((high_2_ls_bits_tmp_40cd9_208) * (M31_128))),
                    ((high_14_ms_bits_col170) - ((high_5_ms_bits_col171) * (M31_512))),
                    high_5_ms_bits_col171,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                ];

                let enabler_col173 = enabler_col.packed_at(row_index);
                *row[173] = enabler_col173;
                *lookup_data.opcodes_72 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_73 = [
                    M31_428564188,
                    ((input_pc_col0) + (M31_1)),
                    ((input_ap_col1) + (ap_update_add_1_col9)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col173;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `blake_compress_opcode` — mechanical rewrite of
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
//     range_check_7_2_5_7[4] 107..110
//     memory_address_to_id_8[3] 111..113
//     memory_id_to_big_9[30] 114..143
//     range_check_7_2_5_10[4] 144..147
//     memory_address_to_id_11[3] 148..150
//     memory_id_to_big_12[30] 151..180
//     range_check_7_2_5_13[4] 181..184
//     memory_address_to_id_14[3] 185..187
//     memory_id_to_big_15[30] 188..217
//     range_check_7_2_5_16[4] 218..221
//     memory_address_to_id_17[3] 222..224
//     memory_id_to_big_18[30] 225..254
//     range_check_7_2_5_19[4] 255..258
//     memory_address_to_id_20[3] 259..261
//     memory_id_to_big_21[30] 262..291
//     range_check_7_2_5_22[4] 292..295
//     memory_address_to_id_23[3] 296..298
//     memory_id_to_big_24[30] 299..328
//     range_check_7_2_5_25[4] 329..332
//     memory_address_to_id_26[3] 333..335
//     memory_id_to_big_27[30] 336..365
//     range_check_7_2_5_28[4] 366..369
//     memory_address_to_id_29[3] 370..372
//     memory_id_to_big_30[30] 373..402
//     range_check_7_2_5_31[4] 403..406
//     memory_address_to_id_32[3] 407..409
//     memory_id_to_big_33[30] 410..439
//     verify_bitwise_xor_8_34[4] 440..443
//     verify_bitwise_xor_8_35[4] 444..447
//     verify_bitwise_xor_8_36[4] 448..451
//     verify_bitwise_xor_8_37[4] 452..455
//     blake_round_38[36] 456..491
//     blake_round_39[36] 492..527
//     triple_xor_32_40[9] 528..536
//     triple_xor_32_41[9] 537..545
//     triple_xor_32_42[9] 546..554
//     triple_xor_32_43[9] 555..563
//     triple_xor_32_44[9] 564..572
//     triple_xor_32_45[9] 573..581
//     triple_xor_32_46[9] 582..590
//     triple_xor_32_47[9] 591..599
//     range_check_7_2_5_48[4] 600..603
//     memory_address_to_id_49[3] 604..606
//     memory_id_to_big_50[30] 607..636
//     range_check_7_2_5_51[4] 637..640
//     memory_address_to_id_52[3] 641..643
//     memory_id_to_big_53[30] 644..673
//     range_check_7_2_5_54[4] 674..677
//     memory_address_to_id_55[3] 678..680
//     memory_id_to_big_56[30] 681..710
//     range_check_7_2_5_57[4] 711..714
//     memory_address_to_id_58[3] 715..717
//     memory_id_to_big_59[30] 718..747
//     range_check_7_2_5_60[4] 748..751
//     memory_address_to_id_61[3] 752..754
//     memory_id_to_big_62[30] 755..784
//     range_check_7_2_5_63[4] 785..788
//     memory_address_to_id_64[3] 789..791
//     memory_id_to_big_65[30] 792..821
//     range_check_7_2_5_66[4] 822..825
//     memory_address_to_id_67[3] 826..828
//     memory_id_to_big_68[30] 829..858
//     range_check_7_2_5_69[4] 859..862
//     memory_address_to_id_70[3] 863..865
//     memory_id_to_big_71[30] 866..895
//     opcodes_72[4] 896..899
//     opcodes_73[4] 900..903
//     mults_0 904
//     mults_1 905
//     (906 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     memory_address_to_id[2] 9
//     memory_address_to_id[3] 10
//     memory_address_to_id[4] 11
//     memory_address_to_id[5] 12
//     memory_address_to_id[6] 13
//     memory_address_to_id[7] 14
//     memory_address_to_id[8] 15
//     memory_address_to_id[9] 16
//     memory_address_to_id[10] 17
//     memory_address_to_id[11] 18
//     memory_address_to_id[12] 19
//     memory_address_to_id[13] 20
//     memory_address_to_id[14] 21
//     memory_address_to_id[15] 22
//     memory_address_to_id[16] 23
//     memory_address_to_id[17] 24
//     memory_address_to_id[18] 25
//     memory_address_to_id[19] 26
//     memory_id_to_big[0] 27
//     memory_id_to_big[1] 28
//     memory_id_to_big[2] 29
//     memory_id_to_big[3] 30
//     memory_id_to_big[4] 31
//     memory_id_to_big[5] 32
//     memory_id_to_big[6] 33
//     memory_id_to_big[7] 34
//     memory_id_to_big[8] 35
//     memory_id_to_big[9] 36
//     memory_id_to_big[10] 37
//     memory_id_to_big[11] 38
//     memory_id_to_big[12] 39
//     memory_id_to_big[13] 40
//     memory_id_to_big[14] 41
//     memory_id_to_big[15] 42
//     memory_id_to_big[16] 43
//     memory_id_to_big[17] 44
//     memory_id_to_big[18] 45
//     memory_id_to_big[19] 46
//     range_check_7_2_5[0] 47..49
//     range_check_7_2_5[1] 50..52
//     range_check_7_2_5[2] 53..55
//     range_check_7_2_5[3] 56..58
//     range_check_7_2_5[4] 59..61
//     range_check_7_2_5[5] 62..64
//     range_check_7_2_5[6] 65..67
//     range_check_7_2_5[7] 68..70
//     range_check_7_2_5[8] 71..73
//     range_check_7_2_5[9] 74..76
//     range_check_7_2_5[10] 77..79
//     range_check_7_2_5[11] 80..82
//     range_check_7_2_5[12] 83..85
//     range_check_7_2_5[13] 86..88
//     range_check_7_2_5[14] 89..91
//     range_check_7_2_5[15] 92..94
//     range_check_7_2_5[16] 95..97
//     verify_bitwise_xor_8[0] 98..100
//     verify_bitwise_xor_8[1] 101..103
//     verify_bitwise_xor_8[2] 104..106
//     verify_bitwise_xor_8[3] 107..109
//     blake_round[0] 110..128
//     blake_round[1] 129..147
//     blake_round[2] 148..166
//     blake_round[3] 167..185
//     blake_round[4] 186..204
//     blake_round[5] 205..223
//     blake_round[6] 224..242
//     blake_round[7] 243..261
//     blake_round[8] 262..280
//     blake_round[9] 281..299
//     triple_xor_32[0] 300..302
//     triple_xor_32[1] 303..305
//     triple_xor_32[2] 306..308
//     triple_xor_32[3] 309..311
//     triple_xor_32[4] 312..314
//     triple_xor_32[5] 315..317
//     triple_xor_32[6] 318..320
//     triple_xor_32[7] 321..323
//     (324 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 906;
pub(crate) const N_SUB_INPUT_WORDS: usize = 324;

/// The per-row `blake_compress_opcode` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn blake_compress_opcode_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_4 = eval.m31_const(4);
    let m31_5 = eval.m31_const(5);
    let m31_6 = eval.m31_const(6);
    let m31_7 = eval.m31_const(7);
    let m31_8 = eval.m31_const(8);
    let m31_9 = eval.m31_const(9);
    let m31_10 = eval.m31_const(10);
    let m31_14 = eval.m31_const(14);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_81 = eval.m31_const(81);
    let m31_82 = eval.m31_const(82);
    let m31_127 = eval.m31_const(127);
    let m31_128 = eval.m31_const(128);
    let m31_256 = eval.m31_const(256);
    let m31_512 = eval.m31_const(512);
    let m31_2048 = eval.m31_const(2048);
    let m31_8067 = eval.m31_const(8067);
    let m31_9812 = eval.m31_const(9812);
    let m31_15470 = eval.m31_const(15470);
    let m31_23520 = eval.m31_const(23520);
    let m31_26764 = eval.m31_const(26764);
    let m31_27145 = eval.m31_const(27145);
    let m31_32768 = eval.m31_const(32768);
    let m31_39685 = eval.m31_const(39685);
    let m31_42319 = eval.m31_const(42319);
    let m31_44677 = eval.m31_const(44677);
    let m31_47975 = eval.m31_const(47975);
    let m31_52505 = eval.m31_const(52505);
    let m31_55723 = eval.m31_const(55723);
    let m31_57468 = eval.m31_const(57468);
    let m31_58983 = eval.m31_const(58983);
    let m31_62322 = eval.m31_const(62322);
    let m31_62778 = eval.m31_const(62778);
    let m31_262144 = eval.m31_const(262144);
    let m31_40528774 = eval.m31_const(40528774);
    let m31_112558620 = eval.m31_const(112558620);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_371240602 = eval.m31_const(371240602);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_990559919 = eval.m31_const(990559919);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let seq = eval.iota();
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_40cd9_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_40cd9_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_40cd9_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_40cd9_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 1);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 7);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 2);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 2);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 3);
    let wg_v14 = eval.u16_from_m31(wg_v13);
    let wg_v15 = eval.u16_and(wg_v14, 31);
    let wg_v16 = eval.u16_shl(wg_v15, 11);
    let offset1_tmp_40cd9_3 = eval.u16_add(wg_v12, wg_v16);
    let offset1_col4 = eval.u16_as_m31(offset1_tmp_40cd9_3);
    eval.set_col(4, offset1_col4);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 3);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shr(wg_v18, 5);
    let wg_v20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 4);
    let wg_v21 = eval.u16_from_m31(wg_v20);
    let wg_v22 = eval.u16_shl(wg_v21, 4);
    let wg_v23 = eval.u16_add(wg_v19, wg_v22);
    let wg_v24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 5);
    let wg_v25 = eval.u16_from_m31(wg_v24);
    let wg_v26 = eval.u16_and(wg_v25, 7);
    let wg_v27 = eval.u16_shl(wg_v26, 13);
    let offset2_tmp_40cd9_4 = eval.u16_add(wg_v23, wg_v27);
    let offset2_col5 = eval.u16_as_m31(offset2_tmp_40cd9_4);
    eval.set_col(5, offset2_col5);
    let wg_v28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 5);
    let wg_v29 = eval.u16_from_m31(wg_v28);
    let wg_v30 = eval.u16_shr(wg_v29, 3);
    let wg_v31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 6);
    let wg_v32 = eval.u16_from_m31(wg_v31);
    let wg_v33 = eval.u16_shl(wg_v32, 6);
    let wg_v34 = eval.u16_add(wg_v30, wg_v33);
    let wg_v35 = eval.u16_shr(wg_v34, 0);
    let dst_base_fp_tmp_40cd9_5 = eval.u16_and(wg_v35, 1);
    let dst_base_fp_col6 = eval.u16_as_m31(dst_base_fp_tmp_40cd9_5);
    eval.set_col(6, dst_base_fp_col6);
    let wg_v36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 5);
    let wg_v37 = eval.u16_from_m31(wg_v36);
    let wg_v38 = eval.u16_shr(wg_v37, 3);
    let wg_v39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 6);
    let wg_v40 = eval.u16_from_m31(wg_v39);
    let wg_v41 = eval.u16_shl(wg_v40, 6);
    let wg_v42 = eval.u16_add(wg_v38, wg_v41);
    let wg_v43 = eval.u16_shr(wg_v42, 1);
    let op0_base_fp_tmp_40cd9_6 = eval.u16_and(wg_v43, 1);
    let op0_base_fp_col7 = eval.u16_as_m31(op0_base_fp_tmp_40cd9_6);
    eval.set_col(7, op0_base_fp_col7);
    let wg_v44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 5);
    let wg_v45 = eval.u16_from_m31(wg_v44);
    let wg_v46 = eval.u16_shr(wg_v45, 3);
    let wg_v47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 6);
    let wg_v48 = eval.u16_from_m31(wg_v47);
    let wg_v49 = eval.u16_shl(wg_v48, 6);
    let wg_v50 = eval.u16_add(wg_v46, wg_v49);
    let wg_v51 = eval.u16_shr(wg_v50, 3);
    let op1_base_fp_tmp_40cd9_7 = eval.u16_and(wg_v51, 1);
    let op1_base_fp_col8 = eval.u16_as_m31(op1_base_fp_tmp_40cd9_7);
    eval.set_col(8, op1_base_fp_col8);
    let wg_v52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 5);
    let wg_v53 = eval.u16_from_m31(wg_v52);
    let wg_v54 = eval.u16_shr(wg_v53, 3);
    let wg_v55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 6);
    let wg_v56 = eval.u16_from_m31(wg_v55);
    let wg_v57 = eval.u16_shl(wg_v56, 6);
    let wg_v58 = eval.u16_add(wg_v54, wg_v57);
    let wg_v59 = eval.u16_shr(wg_v58, 11);
    let ap_update_add_1_tmp_40cd9_8 = eval.u16_and(wg_v59, 1);
    let ap_update_add_1_col9 = eval.u16_as_m31(ap_update_add_1_tmp_40cd9_8);
    eval.set_col(9, ap_update_add_1_col9);
    let opcode_extension_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_1.clone(), 7);
    eval.set_col(10, opcode_extension_col10);
    let wg_v60 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v61 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v62 = eval.m31_add(wg_v60, wg_v61);
    let wg_v63 = eval.m31_mul(op1_base_fp_col8, m31_64);
    let wg_v64 = eval.m31_add(wg_v62, wg_v63);
    let wg_v65 = eval.m31_sub(m31_1, op1_base_fp_col8);
    let wg_v66 = eval.m31_mul(wg_v65, m31_128);
    let wg_v67 = eval.m31_add(wg_v64, wg_v66);
    let wg_v68 = eval.m31_mul(ap_update_add_1_col9, m31_32);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, offset0_col3);
    eval.set_sub_input_word(2, offset1_col4);
    eval.set_sub_input_word(3, offset2_col5);
    eval.set_sub_input_word(4, wg_v67);
    eval.set_sub_input_word(5, wg_v68);
    eval.set_sub_input_word(6, opcode_extension_col10);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, offset0_col3);
    eval.set_lookup_word(3, offset1_col4);
    eval.set_lookup_word(4, offset2_col5);
    let wg_v69 = eval.m31_mul(dst_base_fp_col6, m31_8);
    let wg_v70 = eval.m31_mul(op0_base_fp_col7, m31_16);
    let wg_v71 = eval.m31_add(wg_v69, wg_v70);
    let wg_v72 = eval.m31_mul(op1_base_fp_col8, m31_64);
    let wg_v73 = eval.m31_add(wg_v71, wg_v72);
    let wg_v74 = eval.m31_sub(m31_1, op1_base_fp_col8);
    let wg_v75 = eval.m31_mul(wg_v74, m31_128);
    let wg_v76 = eval.m31_add(wg_v73, wg_v75);
    eval.set_lookup_word(5, wg_v76);
    let wg_v77 = eval.m31_mul(ap_update_add_1_col9, m31_32);
    eval.set_lookup_word(6, wg_v77);
    eval.set_lookup_word(7, opcode_extension_col10);
    let wg_v78 = eval.m31_sub(offset0_col3, m31_32768);
    let wg_v79 = eval.m31_sub(offset1_col4, m31_32768);
    let wg_v80 = eval.m31_sub(offset2_col5, m31_32768);
    let wg_v81 = eval.m31_sub(m31_1, op1_base_fp_col8);
    let decode_instruction_30129_output_tmp_40cd9_9 = (
        [wg_v78, wg_v79, wg_v80],
        [
            dst_base_fp_col6,
            op0_base_fp_col7,
            m31_0,
            op1_base_fp_col8,
            wg_v81,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            ap_update_add_1_col9,
            m31_0,
            m31_0,
            m31_0,
        ],
        opcode_extension_col10,
    );
    let wg_v82 = eval.m31_mul(op0_base_fp_col7, input_fp_col2);
    let wg_v83 = eval.m31_sub(m31_1, op0_base_fp_col7);
    let wg_v84 = eval.m31_mul(wg_v83, input_ap_col1);
    let mem0_base_col11 = eval.m31_add(wg_v82, wg_v84);
    eval.set_col(11, mem0_base_col11);
    let wg_v85 = eval.m31_add(
        mem0_base_col11,
        decode_instruction_30129_output_tmp_40cd9_9.0[1],
    );
    let memory_address_to_id_value_tmp_40cd9_10 = eval.mem_addr_to_id(wg_v85);
    let op0_id_col12 = memory_address_to_id_value_tmp_40cd9_10;
    eval.set_col(12, op0_id_col12);
    let wg_v86 = eval.m31_add(
        mem0_base_col11,
        decode_instruction_30129_output_tmp_40cd9_9.0[1],
    );
    eval.set_sub_input_word(7, wg_v86);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v87 = eval.m31_add(
        mem0_base_col11,
        decode_instruction_30129_output_tmp_40cd9_9.0[1],
    );
    eval.set_lookup_word(9, wg_v87);
    eval.set_lookup_word(10, op0_id_col12);
    let memory_id_to_big_value_tmp_40cd9_12 = eval.mem_id_to_value(op0_id_col12);
    let op0_limb_0_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_12.clone(), 0);
    eval.set_col(13, op0_limb_0_col13);
    let op0_limb_1_col14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_12.clone(), 1);
    eval.set_col(14, op0_limb_1_col14);
    let op0_limb_2_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_12.clone(), 2);
    eval.set_col(15, op0_limb_2_col15);
    let op0_limb_3_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_12.clone(), 3);
    eval.set_col(16, op0_limb_3_col16);
    let wg_v88 = eval.u16_from_m31(op0_limb_3_col16);
    let wg_v89 = eval.u16_and(wg_v88, 2);
    let partial_limb_msb_tmp_40cd9_13 = eval.u16_shr(wg_v89, 1);
    let partial_limb_msb_col17 = eval.u16_as_m31(partial_limb_msb_tmp_40cd9_13);
    eval.set_col(17, partial_limb_msb_col17);
    eval.set_sub_input_word(27, op0_id_col12);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, op0_id_col12);
    eval.set_lookup_word(13, op0_limb_0_col13);
    eval.set_lookup_word(14, op0_limb_1_col14);
    eval.set_lookup_word(15, op0_limb_2_col15);
    eval.set_lookup_word(16, op0_limb_3_col16);
    eval.set_lookup_word(17, m31_0);
    eval.set_lookup_word(18, m31_0);
    eval.set_lookup_word(19, m31_0);
    eval.set_lookup_word(20, m31_0);
    eval.set_lookup_word(21, m31_0);
    eval.set_lookup_word(22, m31_0);
    eval.set_lookup_word(23, m31_0);
    eval.set_lookup_word(24, m31_0);
    eval.set_lookup_word(25, m31_0);
    eval.set_lookup_word(26, m31_0);
    eval.set_lookup_word(27, m31_0);
    eval.set_lookup_word(28, m31_0);
    eval.set_lookup_word(29, m31_0);
    eval.set_lookup_word(30, m31_0);
    eval.set_lookup_word(31, m31_0);
    eval.set_lookup_word(32, m31_0);
    eval.set_lookup_word(33, m31_0);
    eval.set_lookup_word(34, m31_0);
    eval.set_lookup_word(35, m31_0);
    eval.set_lookup_word(36, m31_0);
    eval.set_lookup_word(37, m31_0);
    eval.set_lookup_word(38, m31_0);
    eval.set_lookup_word(39, m31_0);
    eval.set_lookup_word(40, m31_0);
    let read_positive_known_id_num_bits_29_output_tmp_40cd9_15 = eval.felt_from_limbs([
        op0_limb_0_col13,
        op0_limb_1_col14,
        op0_limb_2_col15,
        op0_limb_3_col16,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
    ]);
    let read_positive_num_bits_29_output_tmp_40cd9_16 = (
        read_positive_known_id_num_bits_29_output_tmp_40cd9_15.clone(),
        op0_id_col12,
    );
    let wg_v90 = eval.m31_mul(op1_base_fp_col8, input_fp_col2);
    let wg_v91 = eval.m31_mul(
        decode_instruction_30129_output_tmp_40cd9_9.1[4],
        input_ap_col1,
    );
    let mem1_base_col18 = eval.m31_add(wg_v90, wg_v91);
    eval.set_col(18, mem1_base_col18);
    let wg_v92 = eval.m31_add(
        mem1_base_col18,
        decode_instruction_30129_output_tmp_40cd9_9.0[2],
    );
    let memory_address_to_id_value_tmp_40cd9_17 = eval.mem_addr_to_id(wg_v92);
    let op1_id_col19 = memory_address_to_id_value_tmp_40cd9_17;
    eval.set_col(19, op1_id_col19);
    let wg_v93 = eval.m31_add(
        mem1_base_col18,
        decode_instruction_30129_output_tmp_40cd9_9.0[2],
    );
    eval.set_sub_input_word(8, wg_v93);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v94 = eval.m31_add(
        mem1_base_col18,
        decode_instruction_30129_output_tmp_40cd9_9.0[2],
    );
    eval.set_lookup_word(42, wg_v94);
    eval.set_lookup_word(43, op1_id_col19);
    let memory_id_to_big_value_tmp_40cd9_19 = eval.mem_id_to_value(op1_id_col19);
    let op1_limb_0_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_19.clone(), 0);
    eval.set_col(20, op1_limb_0_col20);
    let op1_limb_1_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_19.clone(), 1);
    eval.set_col(21, op1_limb_1_col21);
    let op1_limb_2_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_19.clone(), 2);
    eval.set_col(22, op1_limb_2_col22);
    let op1_limb_3_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_19.clone(), 3);
    eval.set_col(23, op1_limb_3_col23);
    let wg_v95 = eval.u16_from_m31(op1_limb_3_col23);
    let wg_v96 = eval.u16_and(wg_v95, 2);
    let partial_limb_msb_tmp_40cd9_20 = eval.u16_shr(wg_v96, 1);
    let partial_limb_msb_col24 = eval.u16_as_m31(partial_limb_msb_tmp_40cd9_20);
    eval.set_col(24, partial_limb_msb_col24);
    eval.set_sub_input_word(28, op1_id_col19);
    eval.set_lookup_word(44, m31_1662111297);
    eval.set_lookup_word(45, op1_id_col19);
    eval.set_lookup_word(46, op1_limb_0_col20);
    eval.set_lookup_word(47, op1_limb_1_col21);
    eval.set_lookup_word(48, op1_limb_2_col22);
    eval.set_lookup_word(49, op1_limb_3_col23);
    eval.set_lookup_word(50, m31_0);
    eval.set_lookup_word(51, m31_0);
    eval.set_lookup_word(52, m31_0);
    eval.set_lookup_word(53, m31_0);
    eval.set_lookup_word(54, m31_0);
    eval.set_lookup_word(55, m31_0);
    eval.set_lookup_word(56, m31_0);
    eval.set_lookup_word(57, m31_0);
    eval.set_lookup_word(58, m31_0);
    eval.set_lookup_word(59, m31_0);
    eval.set_lookup_word(60, m31_0);
    eval.set_lookup_word(61, m31_0);
    eval.set_lookup_word(62, m31_0);
    eval.set_lookup_word(63, m31_0);
    eval.set_lookup_word(64, m31_0);
    eval.set_lookup_word(65, m31_0);
    eval.set_lookup_word(66, m31_0);
    eval.set_lookup_word(67, m31_0);
    eval.set_lookup_word(68, m31_0);
    eval.set_lookup_word(69, m31_0);
    eval.set_lookup_word(70, m31_0);
    eval.set_lookup_word(71, m31_0);
    eval.set_lookup_word(72, m31_0);
    eval.set_lookup_word(73, m31_0);
    let read_positive_known_id_num_bits_29_output_tmp_40cd9_22 = eval.felt_from_limbs([
        op1_limb_0_col20,
        op1_limb_1_col21,
        op1_limb_2_col22,
        op1_limb_3_col23,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
    ]);
    let read_positive_num_bits_29_output_tmp_40cd9_23 = (
        read_positive_known_id_num_bits_29_output_tmp_40cd9_22.clone(),
        op1_id_col19,
    );
    let memory_address_to_id_value_tmp_40cd9_24 = eval.mem_addr_to_id(input_ap_col1);
    let ap_id_col25 = memory_address_to_id_value_tmp_40cd9_24;
    eval.set_col(25, ap_id_col25);
    eval.set_sub_input_word(9, input_ap_col1);
    eval.set_lookup_word(74, m31_1444891767);
    eval.set_lookup_word(75, input_ap_col1);
    eval.set_lookup_word(76, ap_id_col25);
    let memory_id_to_big_value_tmp_40cd9_26 = eval.mem_id_to_value(ap_id_col25);
    let ap_limb_0_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_26.clone(), 0);
    eval.set_col(26, ap_limb_0_col26);
    let ap_limb_1_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_26.clone(), 1);
    eval.set_col(27, ap_limb_1_col27);
    let ap_limb_2_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_26.clone(), 2);
    eval.set_col(28, ap_limb_2_col28);
    let ap_limb_3_col29 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_26.clone(), 3);
    eval.set_col(29, ap_limb_3_col29);
    let wg_v97 = eval.u16_from_m31(ap_limb_3_col29);
    let wg_v98 = eval.u16_and(wg_v97, 2);
    let partial_limb_msb_tmp_40cd9_27 = eval.u16_shr(wg_v98, 1);
    let partial_limb_msb_col30 = eval.u16_as_m31(partial_limb_msb_tmp_40cd9_27);
    eval.set_col(30, partial_limb_msb_col30);
    eval.set_sub_input_word(29, ap_id_col25);
    eval.set_lookup_word(77, m31_1662111297);
    eval.set_lookup_word(78, ap_id_col25);
    eval.set_lookup_word(79, ap_limb_0_col26);
    eval.set_lookup_word(80, ap_limb_1_col27);
    eval.set_lookup_word(81, ap_limb_2_col28);
    eval.set_lookup_word(82, ap_limb_3_col29);
    eval.set_lookup_word(83, m31_0);
    eval.set_lookup_word(84, m31_0);
    eval.set_lookup_word(85, m31_0);
    eval.set_lookup_word(86, m31_0);
    eval.set_lookup_word(87, m31_0);
    eval.set_lookup_word(88, m31_0);
    eval.set_lookup_word(89, m31_0);
    eval.set_lookup_word(90, m31_0);
    eval.set_lookup_word(91, m31_0);
    eval.set_lookup_word(92, m31_0);
    eval.set_lookup_word(93, m31_0);
    eval.set_lookup_word(94, m31_0);
    eval.set_lookup_word(95, m31_0);
    eval.set_lookup_word(96, m31_0);
    eval.set_lookup_word(97, m31_0);
    eval.set_lookup_word(98, m31_0);
    eval.set_lookup_word(99, m31_0);
    eval.set_lookup_word(100, m31_0);
    eval.set_lookup_word(101, m31_0);
    eval.set_lookup_word(102, m31_0);
    eval.set_lookup_word(103, m31_0);
    eval.set_lookup_word(104, m31_0);
    eval.set_lookup_word(105, m31_0);
    eval.set_lookup_word(106, m31_0);
    let read_positive_known_id_num_bits_29_output_tmp_40cd9_29 = eval.felt_from_limbs([
        ap_limb_0_col26,
        ap_limb_1_col27,
        ap_limb_2_col28,
        ap_limb_3_col29,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
        m31_0,
    ]);
    let read_positive_num_bits_29_output_tmp_40cd9_30 = (
        read_positive_known_id_num_bits_29_output_tmp_40cd9_29.clone(),
        ap_id_col25,
    );
    let wg_v99 = eval.m31_mul(dst_base_fp_col6, input_fp_col2);
    let wg_v100 = eval.m31_sub(m31_1, dst_base_fp_col6);
    let wg_v101 = eval.m31_mul(wg_v100, input_ap_col1);
    let mem_dst_base_col31 = eval.m31_add(wg_v99, wg_v101);
    eval.set_col(31, mem_dst_base_col31);
    let wg_v102 = eval.m31_add(
        mem_dst_base_col31,
        decode_instruction_30129_output_tmp_40cd9_9.0[0],
    );
    let memory_address_to_id_value_tmp_40cd9_31 = eval.mem_addr_to_id(wg_v102);
    let memory_id_to_big_value_tmp_40cd9_32 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_31);
    let wg_v103 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_32.clone(), 1);
    let wg_v104 = eval.u16_from_m31(wg_v103);
    let tmp_40cd9_33 = eval.u16_shr(wg_v104, 7);
    let wg_v105 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_32.clone(), 1);
    let wg_v106 = eval.u16_as_m31(tmp_40cd9_33);
    let wg_v107 = eval.m31_mul(wg_v106, m31_128);
    let wg_v108 = eval.m31_sub(wg_v105, wg_v107);
    let wg_v109 = eval.m31_mul(wg_v108, m31_512);
    let wg_v110 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_32.clone(), 0);
    let low_16_bits_col32 = eval.m31_add(wg_v109, wg_v110);
    eval.set_col(32, low_16_bits_col32);
    let wg_v111 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_32.clone(), 3);
    let wg_v112 = eval.m31_mul(wg_v111, m31_2048);
    let wg_v113 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_32.clone(), 2);
    let wg_v114 = eval.m31_mul(wg_v113, m31_4);
    let wg_v115 = eval.m31_add(wg_v112, wg_v114);
    let wg_v116 = eval.u16_as_m31(tmp_40cd9_33);
    let high_16_bits_col33 = eval.m31_add(wg_v115, wg_v116);
    eval.set_col(33, high_16_bits_col33);
    let expected_word_tmp_40cd9_34 = eval.u32_from_limbs(low_16_bits_col32, high_16_bits_col33);
    let wg_v117 = eval.u32_low(expected_word_tmp_40cd9_34);
    let low_7_ms_bits_tmp_40cd9_35 = eval.u16_shr(wg_v117, 9);
    let low_7_ms_bits_col34 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_35);
    eval.set_col(34, low_7_ms_bits_col34);
    let wg_v118 = eval.u32_high(expected_word_tmp_40cd9_34);
    let high_14_ms_bits_tmp_40cd9_36 = eval.u16_shr(wg_v118, 2);
    let high_14_ms_bits_col35 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_36);
    eval.set_col(35, high_14_ms_bits_col35);
    let wg_v119 = eval.m31_mul(high_14_ms_bits_col35, m31_4);
    let high_2_ls_bits_tmp_40cd9_37 = eval.m31_sub(high_16_bits_col33, wg_v119);
    let high_5_ms_bits_tmp_40cd9_38 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_36, 9);
    let high_5_ms_bits_col36 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_38);
    eval.set_col(36, high_5_ms_bits_col36);
    eval.set_sub_input_word(47, low_7_ms_bits_col34);
    eval.set_sub_input_word(48, high_2_ls_bits_tmp_40cd9_37);
    eval.set_sub_input_word(49, high_5_ms_bits_col36);
    eval.set_lookup_word(107, m31_371240602);
    eval.set_lookup_word(108, low_7_ms_bits_col34);
    eval.set_lookup_word(109, high_2_ls_bits_tmp_40cd9_37);
    eval.set_lookup_word(110, high_5_ms_bits_col36);
    let wg_v120 = eval.m31_add(
        mem_dst_base_col31,
        decode_instruction_30129_output_tmp_40cd9_9.0[0],
    );
    let memory_address_to_id_value_tmp_40cd9_39 = eval.mem_addr_to_id(wg_v120);
    let dst_id_col37 = memory_address_to_id_value_tmp_40cd9_39;
    eval.set_col(37, dst_id_col37);
    let wg_v121 = eval.m31_add(
        mem_dst_base_col31,
        decode_instruction_30129_output_tmp_40cd9_9.0[0],
    );
    eval.set_sub_input_word(10, wg_v121);
    eval.set_lookup_word(111, m31_1444891767);
    let wg_v122 = eval.m31_add(
        mem_dst_base_col31,
        decode_instruction_30129_output_tmp_40cd9_9.0[0],
    );
    eval.set_lookup_word(112, wg_v122);
    eval.set_lookup_word(113, dst_id_col37);
    eval.set_sub_input_word(30, dst_id_col37);
    eval.set_lookup_word(114, m31_1662111297);
    eval.set_lookup_word(115, dst_id_col37);
    let wg_v123 = eval.m31_mul(low_7_ms_bits_col34, m31_512);
    let wg_v124 = eval.m31_sub(low_16_bits_col32, wg_v123);
    eval.set_lookup_word(116, wg_v124);
    let wg_v125 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_37, m31_128);
    let wg_v126 = eval.m31_add(low_7_ms_bits_col34, wg_v125);
    eval.set_lookup_word(117, wg_v126);
    let wg_v127 = eval.m31_mul(high_5_ms_bits_col36, m31_512);
    let wg_v128 = eval.m31_sub(high_14_ms_bits_col35, wg_v127);
    eval.set_lookup_word(118, wg_v128);
    eval.set_lookup_word(119, high_5_ms_bits_col36);
    eval.set_lookup_word(120, m31_0);
    eval.set_lookup_word(121, m31_0);
    eval.set_lookup_word(122, m31_0);
    eval.set_lookup_word(123, m31_0);
    eval.set_lookup_word(124, m31_0);
    eval.set_lookup_word(125, m31_0);
    eval.set_lookup_word(126, m31_0);
    eval.set_lookup_word(127, m31_0);
    eval.set_lookup_word(128, m31_0);
    eval.set_lookup_word(129, m31_0);
    eval.set_lookup_word(130, m31_0);
    eval.set_lookup_word(131, m31_0);
    eval.set_lookup_word(132, m31_0);
    eval.set_lookup_word(133, m31_0);
    eval.set_lookup_word(134, m31_0);
    eval.set_lookup_word(135, m31_0);
    eval.set_lookup_word(136, m31_0);
    eval.set_lookup_word(137, m31_0);
    eval.set_lookup_word(138, m31_0);
    eval.set_lookup_word(139, m31_0);
    eval.set_lookup_word(140, m31_0);
    eval.set_lookup_word(141, m31_0);
    eval.set_lookup_word(142, m31_0);
    eval.set_lookup_word(143, m31_0);
    let read_u_32_output_tmp_40cd9_41 = expected_word_tmp_40cd9_34;
    let wg_v129 = eval.m31_mul(op0_limb_1_col14, m31_512);
    let wg_v130 = eval.m31_add(op0_limb_0_col13, wg_v129);
    let wg_v131 = eval.m31_mul(op0_limb_2_col15, m31_262144);
    let wg_v132 = eval.m31_add(wg_v130, wg_v131);
    let wg_v133 = eval.m31_mul(op0_limb_3_col16, m31_134217728);
    let wg_v134 = eval.m31_add(wg_v132, wg_v133);
    let wg_v135 = eval.m31_mul(op1_limb_1_col21, m31_512);
    let wg_v136 = eval.m31_add(op1_limb_0_col20, wg_v135);
    let wg_v137 = eval.m31_mul(op1_limb_2_col22, m31_262144);
    let wg_v138 = eval.m31_add(wg_v136, wg_v137);
    let wg_v139 = eval.m31_mul(op1_limb_3_col23, m31_134217728);
    let wg_v140 = eval.m31_add(wg_v138, wg_v139);
    let wg_v141 = eval.m31_mul(ap_limb_1_col27, m31_512);
    let wg_v142 = eval.m31_add(ap_limb_0_col26, wg_v141);
    let wg_v143 = eval.m31_mul(ap_limb_2_col28, m31_262144);
    let wg_v144 = eval.m31_add(wg_v142, wg_v143);
    let wg_v145 = eval.m31_mul(ap_limb_3_col29, m31_134217728);
    let wg_v146 = eval.m31_add(wg_v144, wg_v145);
    let wg_v147 = eval.mask_from_m31(ap_update_add_1_col9);
    let wg_v148 = eval.m31_sub(opcode_extension_col10, m31_1);
    let wg_v149 = eval.mask_from_m31(wg_v148);
    let decode_blake_opcode_output_tmp_40cd9_42 = (
        [wg_v134, wg_v140, wg_v146],
        read_u_32_output_tmp_40cd9_41,
        [wg_v147, wg_v149],
    );
    let memory_address_to_id_value_tmp_40cd9_43 =
        eval.mem_addr_to_id(decode_blake_opcode_output_tmp_40cd9_42.0[0]);
    let memory_id_to_big_value_tmp_40cd9_44 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_43);
    let wg_v150 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_44.clone(), 1);
    let wg_v151 = eval.u16_from_m31(wg_v150);
    let tmp_40cd9_45 = eval.u16_shr(wg_v151, 7);
    let wg_v152 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_44.clone(), 1);
    let wg_v153 = eval.u16_as_m31(tmp_40cd9_45);
    let wg_v154 = eval.m31_mul(wg_v153, m31_128);
    let wg_v155 = eval.m31_sub(wg_v152, wg_v154);
    let wg_v156 = eval.m31_mul(wg_v155, m31_512);
    let wg_v157 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_44.clone(), 0);
    let low_16_bits_col38 = eval.m31_add(wg_v156, wg_v157);
    eval.set_col(38, low_16_bits_col38);
    let wg_v158 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_44.clone(), 3);
    let wg_v159 = eval.m31_mul(wg_v158, m31_2048);
    let wg_v160 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_44.clone(), 2);
    let wg_v161 = eval.m31_mul(wg_v160, m31_4);
    let wg_v162 = eval.m31_add(wg_v159, wg_v161);
    let wg_v163 = eval.u16_as_m31(tmp_40cd9_45);
    let high_16_bits_col39 = eval.m31_add(wg_v162, wg_v163);
    eval.set_col(39, high_16_bits_col39);
    let expected_word_tmp_40cd9_46 = eval.u32_from_limbs(low_16_bits_col38, high_16_bits_col39);
    let wg_v164 = eval.u32_low(expected_word_tmp_40cd9_46);
    let low_7_ms_bits_tmp_40cd9_47 = eval.u16_shr(wg_v164, 9);
    let low_7_ms_bits_col40 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_47);
    eval.set_col(40, low_7_ms_bits_col40);
    let wg_v165 = eval.u32_high(expected_word_tmp_40cd9_46);
    let high_14_ms_bits_tmp_40cd9_48 = eval.u16_shr(wg_v165, 2);
    let high_14_ms_bits_col41 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_48);
    eval.set_col(41, high_14_ms_bits_col41);
    let wg_v166 = eval.m31_mul(high_14_ms_bits_col41, m31_4);
    let high_2_ls_bits_tmp_40cd9_49 = eval.m31_sub(high_16_bits_col39, wg_v166);
    let high_5_ms_bits_tmp_40cd9_50 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_48, 9);
    let high_5_ms_bits_col42 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_50);
    eval.set_col(42, high_5_ms_bits_col42);
    eval.set_sub_input_word(50, low_7_ms_bits_col40);
    eval.set_sub_input_word(51, high_2_ls_bits_tmp_40cd9_49);
    eval.set_sub_input_word(52, high_5_ms_bits_col42);
    eval.set_lookup_word(144, m31_371240602);
    eval.set_lookup_word(145, low_7_ms_bits_col40);
    eval.set_lookup_word(146, high_2_ls_bits_tmp_40cd9_49);
    eval.set_lookup_word(147, high_5_ms_bits_col42);
    let memory_address_to_id_value_tmp_40cd9_51 =
        eval.mem_addr_to_id(decode_blake_opcode_output_tmp_40cd9_42.0[0]);
    let state_0_id_col43 = memory_address_to_id_value_tmp_40cd9_51;
    eval.set_col(43, state_0_id_col43);
    eval.set_sub_input_word(11, decode_blake_opcode_output_tmp_40cd9_42.0[0]);
    eval.set_lookup_word(148, m31_1444891767);
    eval.set_lookup_word(149, decode_blake_opcode_output_tmp_40cd9_42.0[0]);
    eval.set_lookup_word(150, state_0_id_col43);
    eval.set_sub_input_word(31, state_0_id_col43);
    eval.set_lookup_word(151, m31_1662111297);
    eval.set_lookup_word(152, state_0_id_col43);
    let wg_v167 = eval.m31_mul(low_7_ms_bits_col40, m31_512);
    let wg_v168 = eval.m31_sub(low_16_bits_col38, wg_v167);
    eval.set_lookup_word(153, wg_v168);
    let wg_v169 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_49, m31_128);
    let wg_v170 = eval.m31_add(low_7_ms_bits_col40, wg_v169);
    eval.set_lookup_word(154, wg_v170);
    let wg_v171 = eval.m31_mul(high_5_ms_bits_col42, m31_512);
    let wg_v172 = eval.m31_sub(high_14_ms_bits_col41, wg_v171);
    eval.set_lookup_word(155, wg_v172);
    eval.set_lookup_word(156, high_5_ms_bits_col42);
    eval.set_lookup_word(157, m31_0);
    eval.set_lookup_word(158, m31_0);
    eval.set_lookup_word(159, m31_0);
    eval.set_lookup_word(160, m31_0);
    eval.set_lookup_word(161, m31_0);
    eval.set_lookup_word(162, m31_0);
    eval.set_lookup_word(163, m31_0);
    eval.set_lookup_word(164, m31_0);
    eval.set_lookup_word(165, m31_0);
    eval.set_lookup_word(166, m31_0);
    eval.set_lookup_word(167, m31_0);
    eval.set_lookup_word(168, m31_0);
    eval.set_lookup_word(169, m31_0);
    eval.set_lookup_word(170, m31_0);
    eval.set_lookup_word(171, m31_0);
    eval.set_lookup_word(172, m31_0);
    eval.set_lookup_word(173, m31_0);
    eval.set_lookup_word(174, m31_0);
    eval.set_lookup_word(175, m31_0);
    eval.set_lookup_word(176, m31_0);
    eval.set_lookup_word(177, m31_0);
    eval.set_lookup_word(178, m31_0);
    eval.set_lookup_word(179, m31_0);
    eval.set_lookup_word(180, m31_0);
    let read_u_32_output_tmp_40cd9_53 = expected_word_tmp_40cd9_46;
    let wg_v173 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_1);
    let memory_address_to_id_value_tmp_40cd9_54 = eval.mem_addr_to_id(wg_v173);
    let memory_id_to_big_value_tmp_40cd9_55 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_54);
    let wg_v174 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_55.clone(), 1);
    let wg_v175 = eval.u16_from_m31(wg_v174);
    let tmp_40cd9_56 = eval.u16_shr(wg_v175, 7);
    let wg_v176 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_55.clone(), 1);
    let wg_v177 = eval.u16_as_m31(tmp_40cd9_56);
    let wg_v178 = eval.m31_mul(wg_v177, m31_128);
    let wg_v179 = eval.m31_sub(wg_v176, wg_v178);
    let wg_v180 = eval.m31_mul(wg_v179, m31_512);
    let wg_v181 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_55.clone(), 0);
    let low_16_bits_col44 = eval.m31_add(wg_v180, wg_v181);
    eval.set_col(44, low_16_bits_col44);
    let wg_v182 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_55.clone(), 3);
    let wg_v183 = eval.m31_mul(wg_v182, m31_2048);
    let wg_v184 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_55.clone(), 2);
    let wg_v185 = eval.m31_mul(wg_v184, m31_4);
    let wg_v186 = eval.m31_add(wg_v183, wg_v185);
    let wg_v187 = eval.u16_as_m31(tmp_40cd9_56);
    let high_16_bits_col45 = eval.m31_add(wg_v186, wg_v187);
    eval.set_col(45, high_16_bits_col45);
    let expected_word_tmp_40cd9_57 = eval.u32_from_limbs(low_16_bits_col44, high_16_bits_col45);
    let wg_v188 = eval.u32_low(expected_word_tmp_40cd9_57);
    let low_7_ms_bits_tmp_40cd9_58 = eval.u16_shr(wg_v188, 9);
    let low_7_ms_bits_col46 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_58);
    eval.set_col(46, low_7_ms_bits_col46);
    let wg_v189 = eval.u32_high(expected_word_tmp_40cd9_57);
    let high_14_ms_bits_tmp_40cd9_59 = eval.u16_shr(wg_v189, 2);
    let high_14_ms_bits_col47 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_59);
    eval.set_col(47, high_14_ms_bits_col47);
    let wg_v190 = eval.m31_mul(high_14_ms_bits_col47, m31_4);
    let high_2_ls_bits_tmp_40cd9_60 = eval.m31_sub(high_16_bits_col45, wg_v190);
    let high_5_ms_bits_tmp_40cd9_61 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_59, 9);
    let high_5_ms_bits_col48 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_61);
    eval.set_col(48, high_5_ms_bits_col48);
    eval.set_sub_input_word(53, low_7_ms_bits_col46);
    eval.set_sub_input_word(54, high_2_ls_bits_tmp_40cd9_60);
    eval.set_sub_input_word(55, high_5_ms_bits_col48);
    eval.set_lookup_word(181, m31_371240602);
    eval.set_lookup_word(182, low_7_ms_bits_col46);
    eval.set_lookup_word(183, high_2_ls_bits_tmp_40cd9_60);
    eval.set_lookup_word(184, high_5_ms_bits_col48);
    let wg_v191 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_1);
    let memory_address_to_id_value_tmp_40cd9_62 = eval.mem_addr_to_id(wg_v191);
    let state_1_id_col49 = memory_address_to_id_value_tmp_40cd9_62;
    eval.set_col(49, state_1_id_col49);
    let wg_v192 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_1);
    eval.set_sub_input_word(12, wg_v192);
    eval.set_lookup_word(185, m31_1444891767);
    let wg_v193 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_1);
    eval.set_lookup_word(186, wg_v193);
    eval.set_lookup_word(187, state_1_id_col49);
    eval.set_sub_input_word(32, state_1_id_col49);
    eval.set_lookup_word(188, m31_1662111297);
    eval.set_lookup_word(189, state_1_id_col49);
    let wg_v194 = eval.m31_mul(low_7_ms_bits_col46, m31_512);
    let wg_v195 = eval.m31_sub(low_16_bits_col44, wg_v194);
    eval.set_lookup_word(190, wg_v195);
    let wg_v196 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_60, m31_128);
    let wg_v197 = eval.m31_add(low_7_ms_bits_col46, wg_v196);
    eval.set_lookup_word(191, wg_v197);
    let wg_v198 = eval.m31_mul(high_5_ms_bits_col48, m31_512);
    let wg_v199 = eval.m31_sub(high_14_ms_bits_col47, wg_v198);
    eval.set_lookup_word(192, wg_v199);
    eval.set_lookup_word(193, high_5_ms_bits_col48);
    eval.set_lookup_word(194, m31_0);
    eval.set_lookup_word(195, m31_0);
    eval.set_lookup_word(196, m31_0);
    eval.set_lookup_word(197, m31_0);
    eval.set_lookup_word(198, m31_0);
    eval.set_lookup_word(199, m31_0);
    eval.set_lookup_word(200, m31_0);
    eval.set_lookup_word(201, m31_0);
    eval.set_lookup_word(202, m31_0);
    eval.set_lookup_word(203, m31_0);
    eval.set_lookup_word(204, m31_0);
    eval.set_lookup_word(205, m31_0);
    eval.set_lookup_word(206, m31_0);
    eval.set_lookup_word(207, m31_0);
    eval.set_lookup_word(208, m31_0);
    eval.set_lookup_word(209, m31_0);
    eval.set_lookup_word(210, m31_0);
    eval.set_lookup_word(211, m31_0);
    eval.set_lookup_word(212, m31_0);
    eval.set_lookup_word(213, m31_0);
    eval.set_lookup_word(214, m31_0);
    eval.set_lookup_word(215, m31_0);
    eval.set_lookup_word(216, m31_0);
    eval.set_lookup_word(217, m31_0);
    let read_u_32_output_tmp_40cd9_64 = expected_word_tmp_40cd9_57;
    let wg_v200 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_2);
    let memory_address_to_id_value_tmp_40cd9_65 = eval.mem_addr_to_id(wg_v200);
    let memory_id_to_big_value_tmp_40cd9_66 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_65);
    let wg_v201 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_66.clone(), 1);
    let wg_v202 = eval.u16_from_m31(wg_v201);
    let tmp_40cd9_67 = eval.u16_shr(wg_v202, 7);
    let wg_v203 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_66.clone(), 1);
    let wg_v204 = eval.u16_as_m31(tmp_40cd9_67);
    let wg_v205 = eval.m31_mul(wg_v204, m31_128);
    let wg_v206 = eval.m31_sub(wg_v203, wg_v205);
    let wg_v207 = eval.m31_mul(wg_v206, m31_512);
    let wg_v208 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_66.clone(), 0);
    let low_16_bits_col50 = eval.m31_add(wg_v207, wg_v208);
    eval.set_col(50, low_16_bits_col50);
    let wg_v209 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_66.clone(), 3);
    let wg_v210 = eval.m31_mul(wg_v209, m31_2048);
    let wg_v211 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_66.clone(), 2);
    let wg_v212 = eval.m31_mul(wg_v211, m31_4);
    let wg_v213 = eval.m31_add(wg_v210, wg_v212);
    let wg_v214 = eval.u16_as_m31(tmp_40cd9_67);
    let high_16_bits_col51 = eval.m31_add(wg_v213, wg_v214);
    eval.set_col(51, high_16_bits_col51);
    let expected_word_tmp_40cd9_68 = eval.u32_from_limbs(low_16_bits_col50, high_16_bits_col51);
    let wg_v215 = eval.u32_low(expected_word_tmp_40cd9_68);
    let low_7_ms_bits_tmp_40cd9_69 = eval.u16_shr(wg_v215, 9);
    let low_7_ms_bits_col52 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_69);
    eval.set_col(52, low_7_ms_bits_col52);
    let wg_v216 = eval.u32_high(expected_word_tmp_40cd9_68);
    let high_14_ms_bits_tmp_40cd9_70 = eval.u16_shr(wg_v216, 2);
    let high_14_ms_bits_col53 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_70);
    eval.set_col(53, high_14_ms_bits_col53);
    let wg_v217 = eval.m31_mul(high_14_ms_bits_col53, m31_4);
    let high_2_ls_bits_tmp_40cd9_71 = eval.m31_sub(high_16_bits_col51, wg_v217);
    let high_5_ms_bits_tmp_40cd9_72 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_70, 9);
    let high_5_ms_bits_col54 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_72);
    eval.set_col(54, high_5_ms_bits_col54);
    eval.set_sub_input_word(56, low_7_ms_bits_col52);
    eval.set_sub_input_word(57, high_2_ls_bits_tmp_40cd9_71);
    eval.set_sub_input_word(58, high_5_ms_bits_col54);
    eval.set_lookup_word(218, m31_371240602);
    eval.set_lookup_word(219, low_7_ms_bits_col52);
    eval.set_lookup_word(220, high_2_ls_bits_tmp_40cd9_71);
    eval.set_lookup_word(221, high_5_ms_bits_col54);
    let wg_v218 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_2);
    let memory_address_to_id_value_tmp_40cd9_73 = eval.mem_addr_to_id(wg_v218);
    let state_2_id_col55 = memory_address_to_id_value_tmp_40cd9_73;
    eval.set_col(55, state_2_id_col55);
    let wg_v219 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_2);
    eval.set_sub_input_word(13, wg_v219);
    eval.set_lookup_word(222, m31_1444891767);
    let wg_v220 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_2);
    eval.set_lookup_word(223, wg_v220);
    eval.set_lookup_word(224, state_2_id_col55);
    eval.set_sub_input_word(33, state_2_id_col55);
    eval.set_lookup_word(225, m31_1662111297);
    eval.set_lookup_word(226, state_2_id_col55);
    let wg_v221 = eval.m31_mul(low_7_ms_bits_col52, m31_512);
    let wg_v222 = eval.m31_sub(low_16_bits_col50, wg_v221);
    eval.set_lookup_word(227, wg_v222);
    let wg_v223 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_71, m31_128);
    let wg_v224 = eval.m31_add(low_7_ms_bits_col52, wg_v223);
    eval.set_lookup_word(228, wg_v224);
    let wg_v225 = eval.m31_mul(high_5_ms_bits_col54, m31_512);
    let wg_v226 = eval.m31_sub(high_14_ms_bits_col53, wg_v225);
    eval.set_lookup_word(229, wg_v226);
    eval.set_lookup_word(230, high_5_ms_bits_col54);
    eval.set_lookup_word(231, m31_0);
    eval.set_lookup_word(232, m31_0);
    eval.set_lookup_word(233, m31_0);
    eval.set_lookup_word(234, m31_0);
    eval.set_lookup_word(235, m31_0);
    eval.set_lookup_word(236, m31_0);
    eval.set_lookup_word(237, m31_0);
    eval.set_lookup_word(238, m31_0);
    eval.set_lookup_word(239, m31_0);
    eval.set_lookup_word(240, m31_0);
    eval.set_lookup_word(241, m31_0);
    eval.set_lookup_word(242, m31_0);
    eval.set_lookup_word(243, m31_0);
    eval.set_lookup_word(244, m31_0);
    eval.set_lookup_word(245, m31_0);
    eval.set_lookup_word(246, m31_0);
    eval.set_lookup_word(247, m31_0);
    eval.set_lookup_word(248, m31_0);
    eval.set_lookup_word(249, m31_0);
    eval.set_lookup_word(250, m31_0);
    eval.set_lookup_word(251, m31_0);
    eval.set_lookup_word(252, m31_0);
    eval.set_lookup_word(253, m31_0);
    eval.set_lookup_word(254, m31_0);
    let read_u_32_output_tmp_40cd9_75 = expected_word_tmp_40cd9_68;
    let wg_v227 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_3);
    let memory_address_to_id_value_tmp_40cd9_76 = eval.mem_addr_to_id(wg_v227);
    let memory_id_to_big_value_tmp_40cd9_77 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_76);
    let wg_v228 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_77.clone(), 1);
    let wg_v229 = eval.u16_from_m31(wg_v228);
    let tmp_40cd9_78 = eval.u16_shr(wg_v229, 7);
    let wg_v230 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_77.clone(), 1);
    let wg_v231 = eval.u16_as_m31(tmp_40cd9_78);
    let wg_v232 = eval.m31_mul(wg_v231, m31_128);
    let wg_v233 = eval.m31_sub(wg_v230, wg_v232);
    let wg_v234 = eval.m31_mul(wg_v233, m31_512);
    let wg_v235 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_77.clone(), 0);
    let low_16_bits_col56 = eval.m31_add(wg_v234, wg_v235);
    eval.set_col(56, low_16_bits_col56);
    let wg_v236 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_77.clone(), 3);
    let wg_v237 = eval.m31_mul(wg_v236, m31_2048);
    let wg_v238 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_77.clone(), 2);
    let wg_v239 = eval.m31_mul(wg_v238, m31_4);
    let wg_v240 = eval.m31_add(wg_v237, wg_v239);
    let wg_v241 = eval.u16_as_m31(tmp_40cd9_78);
    let high_16_bits_col57 = eval.m31_add(wg_v240, wg_v241);
    eval.set_col(57, high_16_bits_col57);
    let expected_word_tmp_40cd9_79 = eval.u32_from_limbs(low_16_bits_col56, high_16_bits_col57);
    let wg_v242 = eval.u32_low(expected_word_tmp_40cd9_79);
    let low_7_ms_bits_tmp_40cd9_80 = eval.u16_shr(wg_v242, 9);
    let low_7_ms_bits_col58 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_80);
    eval.set_col(58, low_7_ms_bits_col58);
    let wg_v243 = eval.u32_high(expected_word_tmp_40cd9_79);
    let high_14_ms_bits_tmp_40cd9_81 = eval.u16_shr(wg_v243, 2);
    let high_14_ms_bits_col59 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_81);
    eval.set_col(59, high_14_ms_bits_col59);
    let wg_v244 = eval.m31_mul(high_14_ms_bits_col59, m31_4);
    let high_2_ls_bits_tmp_40cd9_82 = eval.m31_sub(high_16_bits_col57, wg_v244);
    let high_5_ms_bits_tmp_40cd9_83 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_81, 9);
    let high_5_ms_bits_col60 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_83);
    eval.set_col(60, high_5_ms_bits_col60);
    eval.set_sub_input_word(59, low_7_ms_bits_col58);
    eval.set_sub_input_word(60, high_2_ls_bits_tmp_40cd9_82);
    eval.set_sub_input_word(61, high_5_ms_bits_col60);
    eval.set_lookup_word(255, m31_371240602);
    eval.set_lookup_word(256, low_7_ms_bits_col58);
    eval.set_lookup_word(257, high_2_ls_bits_tmp_40cd9_82);
    eval.set_lookup_word(258, high_5_ms_bits_col60);
    let wg_v245 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_3);
    let memory_address_to_id_value_tmp_40cd9_84 = eval.mem_addr_to_id(wg_v245);
    let state_3_id_col61 = memory_address_to_id_value_tmp_40cd9_84;
    eval.set_col(61, state_3_id_col61);
    let wg_v246 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_3);
    eval.set_sub_input_word(14, wg_v246);
    eval.set_lookup_word(259, m31_1444891767);
    let wg_v247 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_3);
    eval.set_lookup_word(260, wg_v247);
    eval.set_lookup_word(261, state_3_id_col61);
    eval.set_sub_input_word(34, state_3_id_col61);
    eval.set_lookup_word(262, m31_1662111297);
    eval.set_lookup_word(263, state_3_id_col61);
    let wg_v248 = eval.m31_mul(low_7_ms_bits_col58, m31_512);
    let wg_v249 = eval.m31_sub(low_16_bits_col56, wg_v248);
    eval.set_lookup_word(264, wg_v249);
    let wg_v250 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_82, m31_128);
    let wg_v251 = eval.m31_add(low_7_ms_bits_col58, wg_v250);
    eval.set_lookup_word(265, wg_v251);
    let wg_v252 = eval.m31_mul(high_5_ms_bits_col60, m31_512);
    let wg_v253 = eval.m31_sub(high_14_ms_bits_col59, wg_v252);
    eval.set_lookup_word(266, wg_v253);
    eval.set_lookup_word(267, high_5_ms_bits_col60);
    eval.set_lookup_word(268, m31_0);
    eval.set_lookup_word(269, m31_0);
    eval.set_lookup_word(270, m31_0);
    eval.set_lookup_word(271, m31_0);
    eval.set_lookup_word(272, m31_0);
    eval.set_lookup_word(273, m31_0);
    eval.set_lookup_word(274, m31_0);
    eval.set_lookup_word(275, m31_0);
    eval.set_lookup_word(276, m31_0);
    eval.set_lookup_word(277, m31_0);
    eval.set_lookup_word(278, m31_0);
    eval.set_lookup_word(279, m31_0);
    eval.set_lookup_word(280, m31_0);
    eval.set_lookup_word(281, m31_0);
    eval.set_lookup_word(282, m31_0);
    eval.set_lookup_word(283, m31_0);
    eval.set_lookup_word(284, m31_0);
    eval.set_lookup_word(285, m31_0);
    eval.set_lookup_word(286, m31_0);
    eval.set_lookup_word(287, m31_0);
    eval.set_lookup_word(288, m31_0);
    eval.set_lookup_word(289, m31_0);
    eval.set_lookup_word(290, m31_0);
    eval.set_lookup_word(291, m31_0);
    let read_u_32_output_tmp_40cd9_86 = expected_word_tmp_40cd9_79;
    let wg_v254 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_4);
    let memory_address_to_id_value_tmp_40cd9_87 = eval.mem_addr_to_id(wg_v254);
    let memory_id_to_big_value_tmp_40cd9_88 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_87);
    let wg_v255 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_88.clone(), 1);
    let wg_v256 = eval.u16_from_m31(wg_v255);
    let tmp_40cd9_89 = eval.u16_shr(wg_v256, 7);
    let wg_v257 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_88.clone(), 1);
    let wg_v258 = eval.u16_as_m31(tmp_40cd9_89);
    let wg_v259 = eval.m31_mul(wg_v258, m31_128);
    let wg_v260 = eval.m31_sub(wg_v257, wg_v259);
    let wg_v261 = eval.m31_mul(wg_v260, m31_512);
    let wg_v262 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_88.clone(), 0);
    let low_16_bits_col62 = eval.m31_add(wg_v261, wg_v262);
    eval.set_col(62, low_16_bits_col62);
    let wg_v263 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_88.clone(), 3);
    let wg_v264 = eval.m31_mul(wg_v263, m31_2048);
    let wg_v265 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_88.clone(), 2);
    let wg_v266 = eval.m31_mul(wg_v265, m31_4);
    let wg_v267 = eval.m31_add(wg_v264, wg_v266);
    let wg_v268 = eval.u16_as_m31(tmp_40cd9_89);
    let high_16_bits_col63 = eval.m31_add(wg_v267, wg_v268);
    eval.set_col(63, high_16_bits_col63);
    let expected_word_tmp_40cd9_90 = eval.u32_from_limbs(low_16_bits_col62, high_16_bits_col63);
    let wg_v269 = eval.u32_low(expected_word_tmp_40cd9_90);
    let low_7_ms_bits_tmp_40cd9_91 = eval.u16_shr(wg_v269, 9);
    let low_7_ms_bits_col64 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_91);
    eval.set_col(64, low_7_ms_bits_col64);
    let wg_v270 = eval.u32_high(expected_word_tmp_40cd9_90);
    let high_14_ms_bits_tmp_40cd9_92 = eval.u16_shr(wg_v270, 2);
    let high_14_ms_bits_col65 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_92);
    eval.set_col(65, high_14_ms_bits_col65);
    let wg_v271 = eval.m31_mul(high_14_ms_bits_col65, m31_4);
    let high_2_ls_bits_tmp_40cd9_93 = eval.m31_sub(high_16_bits_col63, wg_v271);
    let high_5_ms_bits_tmp_40cd9_94 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_92, 9);
    let high_5_ms_bits_col66 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_94);
    eval.set_col(66, high_5_ms_bits_col66);
    eval.set_sub_input_word(62, low_7_ms_bits_col64);
    eval.set_sub_input_word(63, high_2_ls_bits_tmp_40cd9_93);
    eval.set_sub_input_word(64, high_5_ms_bits_col66);
    eval.set_lookup_word(292, m31_371240602);
    eval.set_lookup_word(293, low_7_ms_bits_col64);
    eval.set_lookup_word(294, high_2_ls_bits_tmp_40cd9_93);
    eval.set_lookup_word(295, high_5_ms_bits_col66);
    let wg_v272 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_4);
    let memory_address_to_id_value_tmp_40cd9_95 = eval.mem_addr_to_id(wg_v272);
    let state_4_id_col67 = memory_address_to_id_value_tmp_40cd9_95;
    eval.set_col(67, state_4_id_col67);
    let wg_v273 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_4);
    eval.set_sub_input_word(15, wg_v273);
    eval.set_lookup_word(296, m31_1444891767);
    let wg_v274 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_4);
    eval.set_lookup_word(297, wg_v274);
    eval.set_lookup_word(298, state_4_id_col67);
    eval.set_sub_input_word(35, state_4_id_col67);
    eval.set_lookup_word(299, m31_1662111297);
    eval.set_lookup_word(300, state_4_id_col67);
    let wg_v275 = eval.m31_mul(low_7_ms_bits_col64, m31_512);
    let wg_v276 = eval.m31_sub(low_16_bits_col62, wg_v275);
    eval.set_lookup_word(301, wg_v276);
    let wg_v277 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_93, m31_128);
    let wg_v278 = eval.m31_add(low_7_ms_bits_col64, wg_v277);
    eval.set_lookup_word(302, wg_v278);
    let wg_v279 = eval.m31_mul(high_5_ms_bits_col66, m31_512);
    let wg_v280 = eval.m31_sub(high_14_ms_bits_col65, wg_v279);
    eval.set_lookup_word(303, wg_v280);
    eval.set_lookup_word(304, high_5_ms_bits_col66);
    eval.set_lookup_word(305, m31_0);
    eval.set_lookup_word(306, m31_0);
    eval.set_lookup_word(307, m31_0);
    eval.set_lookup_word(308, m31_0);
    eval.set_lookup_word(309, m31_0);
    eval.set_lookup_word(310, m31_0);
    eval.set_lookup_word(311, m31_0);
    eval.set_lookup_word(312, m31_0);
    eval.set_lookup_word(313, m31_0);
    eval.set_lookup_word(314, m31_0);
    eval.set_lookup_word(315, m31_0);
    eval.set_lookup_word(316, m31_0);
    eval.set_lookup_word(317, m31_0);
    eval.set_lookup_word(318, m31_0);
    eval.set_lookup_word(319, m31_0);
    eval.set_lookup_word(320, m31_0);
    eval.set_lookup_word(321, m31_0);
    eval.set_lookup_word(322, m31_0);
    eval.set_lookup_word(323, m31_0);
    eval.set_lookup_word(324, m31_0);
    eval.set_lookup_word(325, m31_0);
    eval.set_lookup_word(326, m31_0);
    eval.set_lookup_word(327, m31_0);
    eval.set_lookup_word(328, m31_0);
    let read_u_32_output_tmp_40cd9_97 = expected_word_tmp_40cd9_90;
    let wg_v281 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_5);
    let memory_address_to_id_value_tmp_40cd9_98 = eval.mem_addr_to_id(wg_v281);
    let memory_id_to_big_value_tmp_40cd9_99 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_98);
    let wg_v282 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_99.clone(), 1);
    let wg_v283 = eval.u16_from_m31(wg_v282);
    let tmp_40cd9_100 = eval.u16_shr(wg_v283, 7);
    let wg_v284 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_99.clone(), 1);
    let wg_v285 = eval.u16_as_m31(tmp_40cd9_100);
    let wg_v286 = eval.m31_mul(wg_v285, m31_128);
    let wg_v287 = eval.m31_sub(wg_v284, wg_v286);
    let wg_v288 = eval.m31_mul(wg_v287, m31_512);
    let wg_v289 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_99.clone(), 0);
    let low_16_bits_col68 = eval.m31_add(wg_v288, wg_v289);
    eval.set_col(68, low_16_bits_col68);
    let wg_v290 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_99.clone(), 3);
    let wg_v291 = eval.m31_mul(wg_v290, m31_2048);
    let wg_v292 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_99.clone(), 2);
    let wg_v293 = eval.m31_mul(wg_v292, m31_4);
    let wg_v294 = eval.m31_add(wg_v291, wg_v293);
    let wg_v295 = eval.u16_as_m31(tmp_40cd9_100);
    let high_16_bits_col69 = eval.m31_add(wg_v294, wg_v295);
    eval.set_col(69, high_16_bits_col69);
    let expected_word_tmp_40cd9_101 = eval.u32_from_limbs(low_16_bits_col68, high_16_bits_col69);
    let wg_v296 = eval.u32_low(expected_word_tmp_40cd9_101);
    let low_7_ms_bits_tmp_40cd9_102 = eval.u16_shr(wg_v296, 9);
    let low_7_ms_bits_col70 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_102);
    eval.set_col(70, low_7_ms_bits_col70);
    let wg_v297 = eval.u32_high(expected_word_tmp_40cd9_101);
    let high_14_ms_bits_tmp_40cd9_103 = eval.u16_shr(wg_v297, 2);
    let high_14_ms_bits_col71 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_103);
    eval.set_col(71, high_14_ms_bits_col71);
    let wg_v298 = eval.m31_mul(high_14_ms_bits_col71, m31_4);
    let high_2_ls_bits_tmp_40cd9_104 = eval.m31_sub(high_16_bits_col69, wg_v298);
    let high_5_ms_bits_tmp_40cd9_105 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_103, 9);
    let high_5_ms_bits_col72 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_105);
    eval.set_col(72, high_5_ms_bits_col72);
    eval.set_sub_input_word(65, low_7_ms_bits_col70);
    eval.set_sub_input_word(66, high_2_ls_bits_tmp_40cd9_104);
    eval.set_sub_input_word(67, high_5_ms_bits_col72);
    eval.set_lookup_word(329, m31_371240602);
    eval.set_lookup_word(330, low_7_ms_bits_col70);
    eval.set_lookup_word(331, high_2_ls_bits_tmp_40cd9_104);
    eval.set_lookup_word(332, high_5_ms_bits_col72);
    let wg_v299 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_5);
    let memory_address_to_id_value_tmp_40cd9_106 = eval.mem_addr_to_id(wg_v299);
    let state_5_id_col73 = memory_address_to_id_value_tmp_40cd9_106;
    eval.set_col(73, state_5_id_col73);
    let wg_v300 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_5);
    eval.set_sub_input_word(16, wg_v300);
    eval.set_lookup_word(333, m31_1444891767);
    let wg_v301 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_5);
    eval.set_lookup_word(334, wg_v301);
    eval.set_lookup_word(335, state_5_id_col73);
    eval.set_sub_input_word(36, state_5_id_col73);
    eval.set_lookup_word(336, m31_1662111297);
    eval.set_lookup_word(337, state_5_id_col73);
    let wg_v302 = eval.m31_mul(low_7_ms_bits_col70, m31_512);
    let wg_v303 = eval.m31_sub(low_16_bits_col68, wg_v302);
    eval.set_lookup_word(338, wg_v303);
    let wg_v304 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_104, m31_128);
    let wg_v305 = eval.m31_add(low_7_ms_bits_col70, wg_v304);
    eval.set_lookup_word(339, wg_v305);
    let wg_v306 = eval.m31_mul(high_5_ms_bits_col72, m31_512);
    let wg_v307 = eval.m31_sub(high_14_ms_bits_col71, wg_v306);
    eval.set_lookup_word(340, wg_v307);
    eval.set_lookup_word(341, high_5_ms_bits_col72);
    eval.set_lookup_word(342, m31_0);
    eval.set_lookup_word(343, m31_0);
    eval.set_lookup_word(344, m31_0);
    eval.set_lookup_word(345, m31_0);
    eval.set_lookup_word(346, m31_0);
    eval.set_lookup_word(347, m31_0);
    eval.set_lookup_word(348, m31_0);
    eval.set_lookup_word(349, m31_0);
    eval.set_lookup_word(350, m31_0);
    eval.set_lookup_word(351, m31_0);
    eval.set_lookup_word(352, m31_0);
    eval.set_lookup_word(353, m31_0);
    eval.set_lookup_word(354, m31_0);
    eval.set_lookup_word(355, m31_0);
    eval.set_lookup_word(356, m31_0);
    eval.set_lookup_word(357, m31_0);
    eval.set_lookup_word(358, m31_0);
    eval.set_lookup_word(359, m31_0);
    eval.set_lookup_word(360, m31_0);
    eval.set_lookup_word(361, m31_0);
    eval.set_lookup_word(362, m31_0);
    eval.set_lookup_word(363, m31_0);
    eval.set_lookup_word(364, m31_0);
    eval.set_lookup_word(365, m31_0);
    let read_u_32_output_tmp_40cd9_108 = expected_word_tmp_40cd9_101;
    let wg_v308 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_6);
    let memory_address_to_id_value_tmp_40cd9_109 = eval.mem_addr_to_id(wg_v308);
    let memory_id_to_big_value_tmp_40cd9_110 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_109);
    let wg_v309 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_110.clone(), 1);
    let wg_v310 = eval.u16_from_m31(wg_v309);
    let tmp_40cd9_111 = eval.u16_shr(wg_v310, 7);
    let wg_v311 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_110.clone(), 1);
    let wg_v312 = eval.u16_as_m31(tmp_40cd9_111);
    let wg_v313 = eval.m31_mul(wg_v312, m31_128);
    let wg_v314 = eval.m31_sub(wg_v311, wg_v313);
    let wg_v315 = eval.m31_mul(wg_v314, m31_512);
    let wg_v316 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_110.clone(), 0);
    let low_16_bits_col74 = eval.m31_add(wg_v315, wg_v316);
    eval.set_col(74, low_16_bits_col74);
    let wg_v317 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_110.clone(), 3);
    let wg_v318 = eval.m31_mul(wg_v317, m31_2048);
    let wg_v319 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_110.clone(), 2);
    let wg_v320 = eval.m31_mul(wg_v319, m31_4);
    let wg_v321 = eval.m31_add(wg_v318, wg_v320);
    let wg_v322 = eval.u16_as_m31(tmp_40cd9_111);
    let high_16_bits_col75 = eval.m31_add(wg_v321, wg_v322);
    eval.set_col(75, high_16_bits_col75);
    let expected_word_tmp_40cd9_112 = eval.u32_from_limbs(low_16_bits_col74, high_16_bits_col75);
    let wg_v323 = eval.u32_low(expected_word_tmp_40cd9_112);
    let low_7_ms_bits_tmp_40cd9_113 = eval.u16_shr(wg_v323, 9);
    let low_7_ms_bits_col76 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_113);
    eval.set_col(76, low_7_ms_bits_col76);
    let wg_v324 = eval.u32_high(expected_word_tmp_40cd9_112);
    let high_14_ms_bits_tmp_40cd9_114 = eval.u16_shr(wg_v324, 2);
    let high_14_ms_bits_col77 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_114);
    eval.set_col(77, high_14_ms_bits_col77);
    let wg_v325 = eval.m31_mul(high_14_ms_bits_col77, m31_4);
    let high_2_ls_bits_tmp_40cd9_115 = eval.m31_sub(high_16_bits_col75, wg_v325);
    let high_5_ms_bits_tmp_40cd9_116 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_114, 9);
    let high_5_ms_bits_col78 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_116);
    eval.set_col(78, high_5_ms_bits_col78);
    eval.set_sub_input_word(68, low_7_ms_bits_col76);
    eval.set_sub_input_word(69, high_2_ls_bits_tmp_40cd9_115);
    eval.set_sub_input_word(70, high_5_ms_bits_col78);
    eval.set_lookup_word(366, m31_371240602);
    eval.set_lookup_word(367, low_7_ms_bits_col76);
    eval.set_lookup_word(368, high_2_ls_bits_tmp_40cd9_115);
    eval.set_lookup_word(369, high_5_ms_bits_col78);
    let wg_v326 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_6);
    let memory_address_to_id_value_tmp_40cd9_117 = eval.mem_addr_to_id(wg_v326);
    let state_6_id_col79 = memory_address_to_id_value_tmp_40cd9_117;
    eval.set_col(79, state_6_id_col79);
    let wg_v327 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_6);
    eval.set_sub_input_word(17, wg_v327);
    eval.set_lookup_word(370, m31_1444891767);
    let wg_v328 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_6);
    eval.set_lookup_word(371, wg_v328);
    eval.set_lookup_word(372, state_6_id_col79);
    eval.set_sub_input_word(37, state_6_id_col79);
    eval.set_lookup_word(373, m31_1662111297);
    eval.set_lookup_word(374, state_6_id_col79);
    let wg_v329 = eval.m31_mul(low_7_ms_bits_col76, m31_512);
    let wg_v330 = eval.m31_sub(low_16_bits_col74, wg_v329);
    eval.set_lookup_word(375, wg_v330);
    let wg_v331 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_115, m31_128);
    let wg_v332 = eval.m31_add(low_7_ms_bits_col76, wg_v331);
    eval.set_lookup_word(376, wg_v332);
    let wg_v333 = eval.m31_mul(high_5_ms_bits_col78, m31_512);
    let wg_v334 = eval.m31_sub(high_14_ms_bits_col77, wg_v333);
    eval.set_lookup_word(377, wg_v334);
    eval.set_lookup_word(378, high_5_ms_bits_col78);
    eval.set_lookup_word(379, m31_0);
    eval.set_lookup_word(380, m31_0);
    eval.set_lookup_word(381, m31_0);
    eval.set_lookup_word(382, m31_0);
    eval.set_lookup_word(383, m31_0);
    eval.set_lookup_word(384, m31_0);
    eval.set_lookup_word(385, m31_0);
    eval.set_lookup_word(386, m31_0);
    eval.set_lookup_word(387, m31_0);
    eval.set_lookup_word(388, m31_0);
    eval.set_lookup_word(389, m31_0);
    eval.set_lookup_word(390, m31_0);
    eval.set_lookup_word(391, m31_0);
    eval.set_lookup_word(392, m31_0);
    eval.set_lookup_word(393, m31_0);
    eval.set_lookup_word(394, m31_0);
    eval.set_lookup_word(395, m31_0);
    eval.set_lookup_word(396, m31_0);
    eval.set_lookup_word(397, m31_0);
    eval.set_lookup_word(398, m31_0);
    eval.set_lookup_word(399, m31_0);
    eval.set_lookup_word(400, m31_0);
    eval.set_lookup_word(401, m31_0);
    eval.set_lookup_word(402, m31_0);
    let read_u_32_output_tmp_40cd9_119 = expected_word_tmp_40cd9_112;
    let wg_v335 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_7);
    let memory_address_to_id_value_tmp_40cd9_120 = eval.mem_addr_to_id(wg_v335);
    let memory_id_to_big_value_tmp_40cd9_121 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_40cd9_120);
    let wg_v336 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_121.clone(), 1);
    let wg_v337 = eval.u16_from_m31(wg_v336);
    let tmp_40cd9_122 = eval.u16_shr(wg_v337, 7);
    let wg_v338 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_121.clone(), 1);
    let wg_v339 = eval.u16_as_m31(tmp_40cd9_122);
    let wg_v340 = eval.m31_mul(wg_v339, m31_128);
    let wg_v341 = eval.m31_sub(wg_v338, wg_v340);
    let wg_v342 = eval.m31_mul(wg_v341, m31_512);
    let wg_v343 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_121.clone(), 0);
    let low_16_bits_col80 = eval.m31_add(wg_v342, wg_v343);
    eval.set_col(80, low_16_bits_col80);
    let wg_v344 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_121.clone(), 3);
    let wg_v345 = eval.m31_mul(wg_v344, m31_2048);
    let wg_v346 = eval.felt_get_m31(&memory_id_to_big_value_tmp_40cd9_121.clone(), 2);
    let wg_v347 = eval.m31_mul(wg_v346, m31_4);
    let wg_v348 = eval.m31_add(wg_v345, wg_v347);
    let wg_v349 = eval.u16_as_m31(tmp_40cd9_122);
    let high_16_bits_col81 = eval.m31_add(wg_v348, wg_v349);
    eval.set_col(81, high_16_bits_col81);
    let expected_word_tmp_40cd9_123 = eval.u32_from_limbs(low_16_bits_col80, high_16_bits_col81);
    let wg_v350 = eval.u32_low(expected_word_tmp_40cd9_123);
    let low_7_ms_bits_tmp_40cd9_124 = eval.u16_shr(wg_v350, 9);
    let low_7_ms_bits_col82 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_124);
    eval.set_col(82, low_7_ms_bits_col82);
    let wg_v351 = eval.u32_high(expected_word_tmp_40cd9_123);
    let high_14_ms_bits_tmp_40cd9_125 = eval.u16_shr(wg_v351, 2);
    let high_14_ms_bits_col83 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_125);
    eval.set_col(83, high_14_ms_bits_col83);
    let wg_v352 = eval.m31_mul(high_14_ms_bits_col83, m31_4);
    let high_2_ls_bits_tmp_40cd9_126 = eval.m31_sub(high_16_bits_col81, wg_v352);
    let high_5_ms_bits_tmp_40cd9_127 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_125, 9);
    let high_5_ms_bits_col84 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_127);
    eval.set_col(84, high_5_ms_bits_col84);
    eval.set_sub_input_word(71, low_7_ms_bits_col82);
    eval.set_sub_input_word(72, high_2_ls_bits_tmp_40cd9_126);
    eval.set_sub_input_word(73, high_5_ms_bits_col84);
    eval.set_lookup_word(403, m31_371240602);
    eval.set_lookup_word(404, low_7_ms_bits_col82);
    eval.set_lookup_word(405, high_2_ls_bits_tmp_40cd9_126);
    eval.set_lookup_word(406, high_5_ms_bits_col84);
    let wg_v353 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_7);
    let memory_address_to_id_value_tmp_40cd9_128 = eval.mem_addr_to_id(wg_v353);
    let state_7_id_col85 = memory_address_to_id_value_tmp_40cd9_128;
    eval.set_col(85, state_7_id_col85);
    let wg_v354 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_7);
    eval.set_sub_input_word(18, wg_v354);
    eval.set_lookup_word(407, m31_1444891767);
    let wg_v355 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[0], m31_7);
    eval.set_lookup_word(408, wg_v355);
    eval.set_lookup_word(409, state_7_id_col85);
    eval.set_sub_input_word(38, state_7_id_col85);
    eval.set_lookup_word(410, m31_1662111297);
    eval.set_lookup_word(411, state_7_id_col85);
    let wg_v356 = eval.m31_mul(low_7_ms_bits_col82, m31_512);
    let wg_v357 = eval.m31_sub(low_16_bits_col80, wg_v356);
    eval.set_lookup_word(412, wg_v357);
    let wg_v358 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_126, m31_128);
    let wg_v359 = eval.m31_add(low_7_ms_bits_col82, wg_v358);
    eval.set_lookup_word(413, wg_v359);
    let wg_v360 = eval.m31_mul(high_5_ms_bits_col84, m31_512);
    let wg_v361 = eval.m31_sub(high_14_ms_bits_col83, wg_v360);
    eval.set_lookup_word(414, wg_v361);
    eval.set_lookup_word(415, high_5_ms_bits_col84);
    eval.set_lookup_word(416, m31_0);
    eval.set_lookup_word(417, m31_0);
    eval.set_lookup_word(418, m31_0);
    eval.set_lookup_word(419, m31_0);
    eval.set_lookup_word(420, m31_0);
    eval.set_lookup_word(421, m31_0);
    eval.set_lookup_word(422, m31_0);
    eval.set_lookup_word(423, m31_0);
    eval.set_lookup_word(424, m31_0);
    eval.set_lookup_word(425, m31_0);
    eval.set_lookup_word(426, m31_0);
    eval.set_lookup_word(427, m31_0);
    eval.set_lookup_word(428, m31_0);
    eval.set_lookup_word(429, m31_0);
    eval.set_lookup_word(430, m31_0);
    eval.set_lookup_word(431, m31_0);
    eval.set_lookup_word(432, m31_0);
    eval.set_lookup_word(433, m31_0);
    eval.set_lookup_word(434, m31_0);
    eval.set_lookup_word(435, m31_0);
    eval.set_lookup_word(436, m31_0);
    eval.set_lookup_word(437, m31_0);
    eval.set_lookup_word(438, m31_0);
    eval.set_lookup_word(439, m31_0);
    let read_u_32_output_tmp_40cd9_130 = expected_word_tmp_40cd9_123;
    let wg_v362 = eval.u32_low(decode_blake_opcode_output_tmp_40cd9_42.1);
    let ms_8_bits_tmp_40cd9_131 = eval.u16_shr(wg_v362, 8);
    let ms_8_bits_col86 = eval.u16_as_m31(ms_8_bits_tmp_40cd9_131);
    eval.set_col(86, ms_8_bits_col86);
    let wg_v363 = eval.m31_mul(ms_8_bits_col86, m31_256);
    let wg_v364 = eval.m31_sub(low_16_bits_col32, wg_v363);
    let split_16_low_part_size_8_output_tmp_40cd9_132 = [wg_v364, ms_8_bits_col86];
    let wg_v365 = eval.u32_high(decode_blake_opcode_output_tmp_40cd9_42.1);
    let ms_8_bits_tmp_40cd9_133 = eval.u16_shr(wg_v365, 8);
    let ms_8_bits_col87 = eval.u16_as_m31(ms_8_bits_tmp_40cd9_133);
    eval.set_col(87, ms_8_bits_col87);
    let wg_v366 = eval.m31_mul(ms_8_bits_col87, m31_256);
    let wg_v367 = eval.m31_sub(high_16_bits_col33, wg_v366);
    let split_16_low_part_size_8_output_tmp_40cd9_134 = [wg_v367, ms_8_bits_col87];
    let wg_v368 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_40cd9_132[0]);
    let wg_v369 = eval.u16_from_m31(m31_127);
    let xor_tmp_40cd9_135 = eval.u16_xor(wg_v368, wg_v369);
    let xor_col88 = eval.u16_as_m31(xor_tmp_40cd9_135);
    eval.set_col(88, xor_col88);
    eval.set_sub_input_word(98, split_16_low_part_size_8_output_tmp_40cd9_132[0]);
    eval.set_sub_input_word(99, m31_127);
    eval.set_sub_input_word(100, xor_col88);
    eval.set_lookup_word(440, m31_112558620);
    eval.set_lookup_word(441, split_16_low_part_size_8_output_tmp_40cd9_132[0]);
    eval.set_lookup_word(442, m31_127);
    eval.set_lookup_word(443, xor_col88);
    let wg_v370 = eval.u16_from_m31(ms_8_bits_col86);
    let wg_v371 = eval.u16_from_m31(m31_82);
    let xor_tmp_40cd9_137 = eval.u16_xor(wg_v370, wg_v371);
    let xor_col89 = eval.u16_as_m31(xor_tmp_40cd9_137);
    eval.set_col(89, xor_col89);
    eval.set_sub_input_word(101, ms_8_bits_col86);
    eval.set_sub_input_word(102, m31_82);
    eval.set_sub_input_word(103, xor_col89);
    eval.set_lookup_word(444, m31_112558620);
    eval.set_lookup_word(445, ms_8_bits_col86);
    eval.set_lookup_word(446, m31_82);
    eval.set_lookup_word(447, xor_col89);
    let wg_v372 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_40cd9_134[0]);
    let wg_v373 = eval.u16_from_m31(m31_14);
    let xor_tmp_40cd9_139 = eval.u16_xor(wg_v372, wg_v373);
    let xor_col90 = eval.u16_as_m31(xor_tmp_40cd9_139);
    eval.set_col(90, xor_col90);
    eval.set_sub_input_word(104, split_16_low_part_size_8_output_tmp_40cd9_134[0]);
    eval.set_sub_input_word(105, m31_14);
    eval.set_sub_input_word(106, xor_col90);
    eval.set_lookup_word(448, m31_112558620);
    eval.set_lookup_word(449, split_16_low_part_size_8_output_tmp_40cd9_134[0]);
    eval.set_lookup_word(450, m31_14);
    eval.set_lookup_word(451, xor_col90);
    let wg_v374 = eval.u16_from_m31(ms_8_bits_col87);
    let wg_v375 = eval.u16_from_m31(m31_81);
    let xor_tmp_40cd9_141 = eval.u16_xor(wg_v374, wg_v375);
    let xor_col91 = eval.u16_as_m31(xor_tmp_40cd9_141);
    eval.set_col(91, xor_col91);
    eval.set_sub_input_word(107, ms_8_bits_col87);
    eval.set_sub_input_word(108, m31_81);
    eval.set_sub_input_word(109, xor_col91);
    eval.set_lookup_word(452, m31_112558620);
    eval.set_lookup_word(453, ms_8_bits_col87);
    eval.set_lookup_word(454, m31_81);
    eval.set_lookup_word(455, xor_col91);
    let wg_v376 = eval.u32_const(1779033703);
    let wg_v377 = eval.u32_const(3144134277);
    let wg_v378 = eval.u32_const(1013904242);
    let wg_v379 = eval.u32_const(2773480762);
    let wg_v380 = eval.m31_mul(xor_col89, m31_256);
    let wg_v381 = eval.m31_add(xor_col88, wg_v380);
    let wg_v382 = eval.m31_mul(xor_col91, m31_256);
    let wg_v383 = eval.m31_add(xor_col90, wg_v382);
    let wg_v384 = eval.u32_from_limbs(wg_v381, wg_v383);
    let wg_v385 = eval.u32_const(2600822924);
    let wg_v386 = eval.mask_as_m31(decode_blake_opcode_output_tmp_40cd9_42.2[1]);
    let wg_v387 = eval.m31_mul(wg_v386, m31_9812);
    let wg_v388 = eval.mask_as_m31(decode_blake_opcode_output_tmp_40cd9_42.2[1]);
    let wg_v389 = eval.m31_sub(m31_1, wg_v388);
    let wg_v390 = eval.m31_mul(wg_v389, m31_55723);
    let wg_v391 = eval.m31_add(wg_v387, wg_v390);
    let wg_v392 = eval.mask_as_m31(decode_blake_opcode_output_tmp_40cd9_42.2[1]);
    let wg_v393 = eval.m31_mul(wg_v392, m31_57468);
    let wg_v394 = eval.mask_as_m31(decode_blake_opcode_output_tmp_40cd9_42.2[1]);
    let wg_v395 = eval.m31_sub(m31_1, wg_v394);
    let wg_v396 = eval.m31_mul(wg_v395, m31_8067);
    let wg_v397 = eval.m31_add(wg_v393, wg_v396);
    let wg_v398 = eval.u32_from_limbs(wg_v391, wg_v397);
    let wg_v399 = eval.u32_const(1541459225);
    let create_blake_round_input_output_tmp_40cd9_143 = [
        read_u_32_output_tmp_40cd9_53,
        read_u_32_output_tmp_40cd9_64,
        read_u_32_output_tmp_40cd9_75,
        read_u_32_output_tmp_40cd9_86,
        read_u_32_output_tmp_40cd9_97,
        read_u_32_output_tmp_40cd9_108,
        read_u_32_output_tmp_40cd9_119,
        read_u_32_output_tmp_40cd9_130,
        wg_v376,
        wg_v377,
        wg_v378,
        wg_v379,
        wg_v384,
        wg_v385,
        wg_v398,
        wg_v399,
    ];
    eval.set_lookup_word(456, m31_40528774);
    eval.set_lookup_word(457, seq);
    eval.set_lookup_word(458, m31_0);
    eval.set_lookup_word(459, low_16_bits_col38);
    eval.set_lookup_word(460, high_16_bits_col39);
    eval.set_lookup_word(461, low_16_bits_col44);
    eval.set_lookup_word(462, high_16_bits_col45);
    eval.set_lookup_word(463, low_16_bits_col50);
    eval.set_lookup_word(464, high_16_bits_col51);
    eval.set_lookup_word(465, low_16_bits_col56);
    eval.set_lookup_word(466, high_16_bits_col57);
    eval.set_lookup_word(467, low_16_bits_col62);
    eval.set_lookup_word(468, high_16_bits_col63);
    eval.set_lookup_word(469, low_16_bits_col68);
    eval.set_lookup_word(470, high_16_bits_col69);
    eval.set_lookup_word(471, low_16_bits_col74);
    eval.set_lookup_word(472, high_16_bits_col75);
    eval.set_lookup_word(473, low_16_bits_col80);
    eval.set_lookup_word(474, high_16_bits_col81);
    eval.set_lookup_word(475, m31_58983);
    eval.set_lookup_word(476, m31_27145);
    eval.set_lookup_word(477, m31_44677);
    eval.set_lookup_word(478, m31_47975);
    eval.set_lookup_word(479, m31_62322);
    eval.set_lookup_word(480, m31_15470);
    eval.set_lookup_word(481, m31_62778);
    eval.set_lookup_word(482, m31_42319);
    let wg_v400 = eval.u32_low(create_blake_round_input_output_tmp_40cd9_143[12]);
    let wg_v401 = eval.u16_as_m31(wg_v400);
    eval.set_lookup_word(483, wg_v401);
    let wg_v402 = eval.u32_high(create_blake_round_input_output_tmp_40cd9_143[12]);
    let wg_v403 = eval.u16_as_m31(wg_v402);
    eval.set_lookup_word(484, wg_v403);
    eval.set_lookup_word(485, m31_26764);
    eval.set_lookup_word(486, m31_39685);
    let wg_v404 = eval.u32_low(create_blake_round_input_output_tmp_40cd9_143[14]);
    let wg_v405 = eval.u16_as_m31(wg_v404);
    eval.set_lookup_word(487, wg_v405);
    let wg_v406 = eval.u32_high(create_blake_round_input_output_tmp_40cd9_143[14]);
    let wg_v407 = eval.u16_as_m31(wg_v406);
    eval.set_lookup_word(488, wg_v407);
    eval.set_lookup_word(489, m31_52505);
    eval.set_lookup_word(490, m31_23520);
    eval.set_lookup_word(491, decode_blake_opcode_output_tmp_40cd9_42.0[1]);
    let wg_v408 = eval.u32_const(1779033703);
    let wg_v409 = eval.u32_const(3144134277);
    let wg_v410 = eval.u32_const(1013904242);
    let wg_v411 = eval.u32_const(2773480762);
    let wg_v412 = eval.u32_const(2600822924);
    let wg_v413 = eval.u32_const(1541459225);
    eval.set_sub_input_word(110, seq);
    eval.set_sub_input_word(111, m31_0);
    eval.set_sub_input_word_u32(112, create_blake_round_input_output_tmp_40cd9_143[0]);
    eval.set_sub_input_word_u32(113, create_blake_round_input_output_tmp_40cd9_143[1]);
    eval.set_sub_input_word_u32(114, create_blake_round_input_output_tmp_40cd9_143[2]);
    eval.set_sub_input_word_u32(115, create_blake_round_input_output_tmp_40cd9_143[3]);
    eval.set_sub_input_word_u32(116, create_blake_round_input_output_tmp_40cd9_143[4]);
    eval.set_sub_input_word_u32(117, create_blake_round_input_output_tmp_40cd9_143[5]);
    eval.set_sub_input_word_u32(118, create_blake_round_input_output_tmp_40cd9_143[6]);
    eval.set_sub_input_word_u32(119, create_blake_round_input_output_tmp_40cd9_143[7]);
    eval.set_sub_input_word_u32(120, wg_v408);
    eval.set_sub_input_word_u32(121, wg_v409);
    eval.set_sub_input_word_u32(122, wg_v410);
    eval.set_sub_input_word_u32(123, wg_v411);
    eval.set_sub_input_word_u32(124, create_blake_round_input_output_tmp_40cd9_143[12]);
    eval.set_sub_input_word_u32(125, wg_v412);
    eval.set_sub_input_word_u32(126, create_blake_round_input_output_tmp_40cd9_143[14]);
    eval.set_sub_input_word_u32(127, wg_v413);
    eval.set_sub_input_word(128, decode_blake_opcode_output_tmp_40cd9_42.0[1]);
    let wg_v414 = eval.u32_const(1779033703);
    let wg_v415 = eval.u32_const(3144134277);
    let wg_v416 = eval.u32_const(1013904242);
    let wg_v417 = eval.u32_const(2773480762);
    let wg_v418 = eval.u32_const(2600822924);
    let wg_v419 = eval.u32_const(1541459225);
    let blake_round_output_round_0_tmp_40cd9_145 = eval.deduce_blake_round(
        seq,
        m31_0,
        [
            create_blake_round_input_output_tmp_40cd9_143[0],
            create_blake_round_input_output_tmp_40cd9_143[1],
            create_blake_round_input_output_tmp_40cd9_143[2],
            create_blake_round_input_output_tmp_40cd9_143[3],
            create_blake_round_input_output_tmp_40cd9_143[4],
            create_blake_round_input_output_tmp_40cd9_143[5],
            create_blake_round_input_output_tmp_40cd9_143[6],
            create_blake_round_input_output_tmp_40cd9_143[7],
            wg_v414,
            wg_v415,
            wg_v416,
            wg_v417,
            create_blake_round_input_output_tmp_40cd9_143[12],
            wg_v418,
            create_blake_round_input_output_tmp_40cd9_143[14],
            wg_v419,
        ],
        decode_blake_opcode_output_tmp_40cd9_42.0[1],
    );
    eval.set_sub_input_word(129, seq);
    eval.set_sub_input_word(130, m31_1);
    eval.set_sub_input_word_u32(131, blake_round_output_round_0_tmp_40cd9_145.2 .0[0]);
    eval.set_sub_input_word_u32(132, blake_round_output_round_0_tmp_40cd9_145.2 .0[1]);
    eval.set_sub_input_word_u32(133, blake_round_output_round_0_tmp_40cd9_145.2 .0[2]);
    eval.set_sub_input_word_u32(134, blake_round_output_round_0_tmp_40cd9_145.2 .0[3]);
    eval.set_sub_input_word_u32(135, blake_round_output_round_0_tmp_40cd9_145.2 .0[4]);
    eval.set_sub_input_word_u32(136, blake_round_output_round_0_tmp_40cd9_145.2 .0[5]);
    eval.set_sub_input_word_u32(137, blake_round_output_round_0_tmp_40cd9_145.2 .0[6]);
    eval.set_sub_input_word_u32(138, blake_round_output_round_0_tmp_40cd9_145.2 .0[7]);
    eval.set_sub_input_word_u32(139, blake_round_output_round_0_tmp_40cd9_145.2 .0[8]);
    eval.set_sub_input_word_u32(140, blake_round_output_round_0_tmp_40cd9_145.2 .0[9]);
    eval.set_sub_input_word_u32(141, blake_round_output_round_0_tmp_40cd9_145.2 .0[10]);
    eval.set_sub_input_word_u32(142, blake_round_output_round_0_tmp_40cd9_145.2 .0[11]);
    eval.set_sub_input_word_u32(143, blake_round_output_round_0_tmp_40cd9_145.2 .0[12]);
    eval.set_sub_input_word_u32(144, blake_round_output_round_0_tmp_40cd9_145.2 .0[13]);
    eval.set_sub_input_word_u32(145, blake_round_output_round_0_tmp_40cd9_145.2 .0[14]);
    eval.set_sub_input_word_u32(146, blake_round_output_round_0_tmp_40cd9_145.2 .0[15]);
    eval.set_sub_input_word(147, blake_round_output_round_0_tmp_40cd9_145.2 .1);
    let blake_round_output_round_1_tmp_40cd9_146 = eval.deduce_blake_round(
        seq,
        m31_1,
        [
            blake_round_output_round_0_tmp_40cd9_145.2 .0[0],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[1],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[2],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[3],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[4],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[5],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[6],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[7],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[8],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[9],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[10],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[11],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[12],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[13],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[14],
            blake_round_output_round_0_tmp_40cd9_145.2 .0[15],
        ],
        blake_round_output_round_0_tmp_40cd9_145.2 .1,
    );
    eval.set_sub_input_word(148, seq);
    eval.set_sub_input_word(149, m31_2);
    eval.set_sub_input_word_u32(150, blake_round_output_round_1_tmp_40cd9_146.2 .0[0]);
    eval.set_sub_input_word_u32(151, blake_round_output_round_1_tmp_40cd9_146.2 .0[1]);
    eval.set_sub_input_word_u32(152, blake_round_output_round_1_tmp_40cd9_146.2 .0[2]);
    eval.set_sub_input_word_u32(153, blake_round_output_round_1_tmp_40cd9_146.2 .0[3]);
    eval.set_sub_input_word_u32(154, blake_round_output_round_1_tmp_40cd9_146.2 .0[4]);
    eval.set_sub_input_word_u32(155, blake_round_output_round_1_tmp_40cd9_146.2 .0[5]);
    eval.set_sub_input_word_u32(156, blake_round_output_round_1_tmp_40cd9_146.2 .0[6]);
    eval.set_sub_input_word_u32(157, blake_round_output_round_1_tmp_40cd9_146.2 .0[7]);
    eval.set_sub_input_word_u32(158, blake_round_output_round_1_tmp_40cd9_146.2 .0[8]);
    eval.set_sub_input_word_u32(159, blake_round_output_round_1_tmp_40cd9_146.2 .0[9]);
    eval.set_sub_input_word_u32(160, blake_round_output_round_1_tmp_40cd9_146.2 .0[10]);
    eval.set_sub_input_word_u32(161, blake_round_output_round_1_tmp_40cd9_146.2 .0[11]);
    eval.set_sub_input_word_u32(162, blake_round_output_round_1_tmp_40cd9_146.2 .0[12]);
    eval.set_sub_input_word_u32(163, blake_round_output_round_1_tmp_40cd9_146.2 .0[13]);
    eval.set_sub_input_word_u32(164, blake_round_output_round_1_tmp_40cd9_146.2 .0[14]);
    eval.set_sub_input_word_u32(165, blake_round_output_round_1_tmp_40cd9_146.2 .0[15]);
    eval.set_sub_input_word(166, blake_round_output_round_1_tmp_40cd9_146.2 .1);
    let blake_round_output_round_2_tmp_40cd9_147 = eval.deduce_blake_round(
        seq,
        m31_2,
        [
            blake_round_output_round_1_tmp_40cd9_146.2 .0[0],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[1],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[2],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[3],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[4],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[5],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[6],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[7],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[8],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[9],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[10],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[11],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[12],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[13],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[14],
            blake_round_output_round_1_tmp_40cd9_146.2 .0[15],
        ],
        blake_round_output_round_1_tmp_40cd9_146.2 .1,
    );
    eval.set_sub_input_word(167, seq);
    eval.set_sub_input_word(168, m31_3);
    eval.set_sub_input_word_u32(169, blake_round_output_round_2_tmp_40cd9_147.2 .0[0]);
    eval.set_sub_input_word_u32(170, blake_round_output_round_2_tmp_40cd9_147.2 .0[1]);
    eval.set_sub_input_word_u32(171, blake_round_output_round_2_tmp_40cd9_147.2 .0[2]);
    eval.set_sub_input_word_u32(172, blake_round_output_round_2_tmp_40cd9_147.2 .0[3]);
    eval.set_sub_input_word_u32(173, blake_round_output_round_2_tmp_40cd9_147.2 .0[4]);
    eval.set_sub_input_word_u32(174, blake_round_output_round_2_tmp_40cd9_147.2 .0[5]);
    eval.set_sub_input_word_u32(175, blake_round_output_round_2_tmp_40cd9_147.2 .0[6]);
    eval.set_sub_input_word_u32(176, blake_round_output_round_2_tmp_40cd9_147.2 .0[7]);
    eval.set_sub_input_word_u32(177, blake_round_output_round_2_tmp_40cd9_147.2 .0[8]);
    eval.set_sub_input_word_u32(178, blake_round_output_round_2_tmp_40cd9_147.2 .0[9]);
    eval.set_sub_input_word_u32(179, blake_round_output_round_2_tmp_40cd9_147.2 .0[10]);
    eval.set_sub_input_word_u32(180, blake_round_output_round_2_tmp_40cd9_147.2 .0[11]);
    eval.set_sub_input_word_u32(181, blake_round_output_round_2_tmp_40cd9_147.2 .0[12]);
    eval.set_sub_input_word_u32(182, blake_round_output_round_2_tmp_40cd9_147.2 .0[13]);
    eval.set_sub_input_word_u32(183, blake_round_output_round_2_tmp_40cd9_147.2 .0[14]);
    eval.set_sub_input_word_u32(184, blake_round_output_round_2_tmp_40cd9_147.2 .0[15]);
    eval.set_sub_input_word(185, blake_round_output_round_2_tmp_40cd9_147.2 .1);
    let blake_round_output_round_3_tmp_40cd9_148 = eval.deduce_blake_round(
        seq,
        m31_3,
        [
            blake_round_output_round_2_tmp_40cd9_147.2 .0[0],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[1],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[2],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[3],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[4],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[5],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[6],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[7],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[8],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[9],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[10],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[11],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[12],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[13],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[14],
            blake_round_output_round_2_tmp_40cd9_147.2 .0[15],
        ],
        blake_round_output_round_2_tmp_40cd9_147.2 .1,
    );
    eval.set_sub_input_word(186, seq);
    eval.set_sub_input_word(187, m31_4);
    eval.set_sub_input_word_u32(188, blake_round_output_round_3_tmp_40cd9_148.2 .0[0]);
    eval.set_sub_input_word_u32(189, blake_round_output_round_3_tmp_40cd9_148.2 .0[1]);
    eval.set_sub_input_word_u32(190, blake_round_output_round_3_tmp_40cd9_148.2 .0[2]);
    eval.set_sub_input_word_u32(191, blake_round_output_round_3_tmp_40cd9_148.2 .0[3]);
    eval.set_sub_input_word_u32(192, blake_round_output_round_3_tmp_40cd9_148.2 .0[4]);
    eval.set_sub_input_word_u32(193, blake_round_output_round_3_tmp_40cd9_148.2 .0[5]);
    eval.set_sub_input_word_u32(194, blake_round_output_round_3_tmp_40cd9_148.2 .0[6]);
    eval.set_sub_input_word_u32(195, blake_round_output_round_3_tmp_40cd9_148.2 .0[7]);
    eval.set_sub_input_word_u32(196, blake_round_output_round_3_tmp_40cd9_148.2 .0[8]);
    eval.set_sub_input_word_u32(197, blake_round_output_round_3_tmp_40cd9_148.2 .0[9]);
    eval.set_sub_input_word_u32(198, blake_round_output_round_3_tmp_40cd9_148.2 .0[10]);
    eval.set_sub_input_word_u32(199, blake_round_output_round_3_tmp_40cd9_148.2 .0[11]);
    eval.set_sub_input_word_u32(200, blake_round_output_round_3_tmp_40cd9_148.2 .0[12]);
    eval.set_sub_input_word_u32(201, blake_round_output_round_3_tmp_40cd9_148.2 .0[13]);
    eval.set_sub_input_word_u32(202, blake_round_output_round_3_tmp_40cd9_148.2 .0[14]);
    eval.set_sub_input_word_u32(203, blake_round_output_round_3_tmp_40cd9_148.2 .0[15]);
    eval.set_sub_input_word(204, blake_round_output_round_3_tmp_40cd9_148.2 .1);
    let blake_round_output_round_4_tmp_40cd9_149 = eval.deduce_blake_round(
        seq,
        m31_4,
        [
            blake_round_output_round_3_tmp_40cd9_148.2 .0[0],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[1],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[2],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[3],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[4],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[5],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[6],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[7],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[8],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[9],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[10],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[11],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[12],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[13],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[14],
            blake_round_output_round_3_tmp_40cd9_148.2 .0[15],
        ],
        blake_round_output_round_3_tmp_40cd9_148.2 .1,
    );
    eval.set_sub_input_word(205, seq);
    eval.set_sub_input_word(206, m31_5);
    eval.set_sub_input_word_u32(207, blake_round_output_round_4_tmp_40cd9_149.2 .0[0]);
    eval.set_sub_input_word_u32(208, blake_round_output_round_4_tmp_40cd9_149.2 .0[1]);
    eval.set_sub_input_word_u32(209, blake_round_output_round_4_tmp_40cd9_149.2 .0[2]);
    eval.set_sub_input_word_u32(210, blake_round_output_round_4_tmp_40cd9_149.2 .0[3]);
    eval.set_sub_input_word_u32(211, blake_round_output_round_4_tmp_40cd9_149.2 .0[4]);
    eval.set_sub_input_word_u32(212, blake_round_output_round_4_tmp_40cd9_149.2 .0[5]);
    eval.set_sub_input_word_u32(213, blake_round_output_round_4_tmp_40cd9_149.2 .0[6]);
    eval.set_sub_input_word_u32(214, blake_round_output_round_4_tmp_40cd9_149.2 .0[7]);
    eval.set_sub_input_word_u32(215, blake_round_output_round_4_tmp_40cd9_149.2 .0[8]);
    eval.set_sub_input_word_u32(216, blake_round_output_round_4_tmp_40cd9_149.2 .0[9]);
    eval.set_sub_input_word_u32(217, blake_round_output_round_4_tmp_40cd9_149.2 .0[10]);
    eval.set_sub_input_word_u32(218, blake_round_output_round_4_tmp_40cd9_149.2 .0[11]);
    eval.set_sub_input_word_u32(219, blake_round_output_round_4_tmp_40cd9_149.2 .0[12]);
    eval.set_sub_input_word_u32(220, blake_round_output_round_4_tmp_40cd9_149.2 .0[13]);
    eval.set_sub_input_word_u32(221, blake_round_output_round_4_tmp_40cd9_149.2 .0[14]);
    eval.set_sub_input_word_u32(222, blake_round_output_round_4_tmp_40cd9_149.2 .0[15]);
    eval.set_sub_input_word(223, blake_round_output_round_4_tmp_40cd9_149.2 .1);
    let blake_round_output_round_5_tmp_40cd9_150 = eval.deduce_blake_round(
        seq,
        m31_5,
        [
            blake_round_output_round_4_tmp_40cd9_149.2 .0[0],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[1],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[2],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[3],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[4],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[5],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[6],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[7],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[8],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[9],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[10],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[11],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[12],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[13],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[14],
            blake_round_output_round_4_tmp_40cd9_149.2 .0[15],
        ],
        blake_round_output_round_4_tmp_40cd9_149.2 .1,
    );
    eval.set_sub_input_word(224, seq);
    eval.set_sub_input_word(225, m31_6);
    eval.set_sub_input_word_u32(226, blake_round_output_round_5_tmp_40cd9_150.2 .0[0]);
    eval.set_sub_input_word_u32(227, blake_round_output_round_5_tmp_40cd9_150.2 .0[1]);
    eval.set_sub_input_word_u32(228, blake_round_output_round_5_tmp_40cd9_150.2 .0[2]);
    eval.set_sub_input_word_u32(229, blake_round_output_round_5_tmp_40cd9_150.2 .0[3]);
    eval.set_sub_input_word_u32(230, blake_round_output_round_5_tmp_40cd9_150.2 .0[4]);
    eval.set_sub_input_word_u32(231, blake_round_output_round_5_tmp_40cd9_150.2 .0[5]);
    eval.set_sub_input_word_u32(232, blake_round_output_round_5_tmp_40cd9_150.2 .0[6]);
    eval.set_sub_input_word_u32(233, blake_round_output_round_5_tmp_40cd9_150.2 .0[7]);
    eval.set_sub_input_word_u32(234, blake_round_output_round_5_tmp_40cd9_150.2 .0[8]);
    eval.set_sub_input_word_u32(235, blake_round_output_round_5_tmp_40cd9_150.2 .0[9]);
    eval.set_sub_input_word_u32(236, blake_round_output_round_5_tmp_40cd9_150.2 .0[10]);
    eval.set_sub_input_word_u32(237, blake_round_output_round_5_tmp_40cd9_150.2 .0[11]);
    eval.set_sub_input_word_u32(238, blake_round_output_round_5_tmp_40cd9_150.2 .0[12]);
    eval.set_sub_input_word_u32(239, blake_round_output_round_5_tmp_40cd9_150.2 .0[13]);
    eval.set_sub_input_word_u32(240, blake_round_output_round_5_tmp_40cd9_150.2 .0[14]);
    eval.set_sub_input_word_u32(241, blake_round_output_round_5_tmp_40cd9_150.2 .0[15]);
    eval.set_sub_input_word(242, blake_round_output_round_5_tmp_40cd9_150.2 .1);
    let blake_round_output_round_6_tmp_40cd9_151 = eval.deduce_blake_round(
        seq,
        m31_6,
        [
            blake_round_output_round_5_tmp_40cd9_150.2 .0[0],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[1],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[2],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[3],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[4],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[5],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[6],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[7],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[8],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[9],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[10],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[11],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[12],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[13],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[14],
            blake_round_output_round_5_tmp_40cd9_150.2 .0[15],
        ],
        blake_round_output_round_5_tmp_40cd9_150.2 .1,
    );
    eval.set_sub_input_word(243, seq);
    eval.set_sub_input_word(244, m31_7);
    eval.set_sub_input_word_u32(245, blake_round_output_round_6_tmp_40cd9_151.2 .0[0]);
    eval.set_sub_input_word_u32(246, blake_round_output_round_6_tmp_40cd9_151.2 .0[1]);
    eval.set_sub_input_word_u32(247, blake_round_output_round_6_tmp_40cd9_151.2 .0[2]);
    eval.set_sub_input_word_u32(248, blake_round_output_round_6_tmp_40cd9_151.2 .0[3]);
    eval.set_sub_input_word_u32(249, blake_round_output_round_6_tmp_40cd9_151.2 .0[4]);
    eval.set_sub_input_word_u32(250, blake_round_output_round_6_tmp_40cd9_151.2 .0[5]);
    eval.set_sub_input_word_u32(251, blake_round_output_round_6_tmp_40cd9_151.2 .0[6]);
    eval.set_sub_input_word_u32(252, blake_round_output_round_6_tmp_40cd9_151.2 .0[7]);
    eval.set_sub_input_word_u32(253, blake_round_output_round_6_tmp_40cd9_151.2 .0[8]);
    eval.set_sub_input_word_u32(254, blake_round_output_round_6_tmp_40cd9_151.2 .0[9]);
    eval.set_sub_input_word_u32(255, blake_round_output_round_6_tmp_40cd9_151.2 .0[10]);
    eval.set_sub_input_word_u32(256, blake_round_output_round_6_tmp_40cd9_151.2 .0[11]);
    eval.set_sub_input_word_u32(257, blake_round_output_round_6_tmp_40cd9_151.2 .0[12]);
    eval.set_sub_input_word_u32(258, blake_round_output_round_6_tmp_40cd9_151.2 .0[13]);
    eval.set_sub_input_word_u32(259, blake_round_output_round_6_tmp_40cd9_151.2 .0[14]);
    eval.set_sub_input_word_u32(260, blake_round_output_round_6_tmp_40cd9_151.2 .0[15]);
    eval.set_sub_input_word(261, blake_round_output_round_6_tmp_40cd9_151.2 .1);
    let blake_round_output_round_7_tmp_40cd9_152 = eval.deduce_blake_round(
        seq,
        m31_7,
        [
            blake_round_output_round_6_tmp_40cd9_151.2 .0[0],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[1],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[2],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[3],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[4],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[5],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[6],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[7],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[8],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[9],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[10],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[11],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[12],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[13],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[14],
            blake_round_output_round_6_tmp_40cd9_151.2 .0[15],
        ],
        blake_round_output_round_6_tmp_40cd9_151.2 .1,
    );
    eval.set_sub_input_word(262, seq);
    eval.set_sub_input_word(263, m31_8);
    eval.set_sub_input_word_u32(264, blake_round_output_round_7_tmp_40cd9_152.2 .0[0]);
    eval.set_sub_input_word_u32(265, blake_round_output_round_7_tmp_40cd9_152.2 .0[1]);
    eval.set_sub_input_word_u32(266, blake_round_output_round_7_tmp_40cd9_152.2 .0[2]);
    eval.set_sub_input_word_u32(267, blake_round_output_round_7_tmp_40cd9_152.2 .0[3]);
    eval.set_sub_input_word_u32(268, blake_round_output_round_7_tmp_40cd9_152.2 .0[4]);
    eval.set_sub_input_word_u32(269, blake_round_output_round_7_tmp_40cd9_152.2 .0[5]);
    eval.set_sub_input_word_u32(270, blake_round_output_round_7_tmp_40cd9_152.2 .0[6]);
    eval.set_sub_input_word_u32(271, blake_round_output_round_7_tmp_40cd9_152.2 .0[7]);
    eval.set_sub_input_word_u32(272, blake_round_output_round_7_tmp_40cd9_152.2 .0[8]);
    eval.set_sub_input_word_u32(273, blake_round_output_round_7_tmp_40cd9_152.2 .0[9]);
    eval.set_sub_input_word_u32(274, blake_round_output_round_7_tmp_40cd9_152.2 .0[10]);
    eval.set_sub_input_word_u32(275, blake_round_output_round_7_tmp_40cd9_152.2 .0[11]);
    eval.set_sub_input_word_u32(276, blake_round_output_round_7_tmp_40cd9_152.2 .0[12]);
    eval.set_sub_input_word_u32(277, blake_round_output_round_7_tmp_40cd9_152.2 .0[13]);
    eval.set_sub_input_word_u32(278, blake_round_output_round_7_tmp_40cd9_152.2 .0[14]);
    eval.set_sub_input_word_u32(279, blake_round_output_round_7_tmp_40cd9_152.2 .0[15]);
    eval.set_sub_input_word(280, blake_round_output_round_7_tmp_40cd9_152.2 .1);
    let blake_round_output_round_8_tmp_40cd9_153 = eval.deduce_blake_round(
        seq,
        m31_8,
        [
            blake_round_output_round_7_tmp_40cd9_152.2 .0[0],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[1],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[2],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[3],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[4],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[5],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[6],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[7],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[8],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[9],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[10],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[11],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[12],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[13],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[14],
            blake_round_output_round_7_tmp_40cd9_152.2 .0[15],
        ],
        blake_round_output_round_7_tmp_40cd9_152.2 .1,
    );
    eval.set_sub_input_word(281, seq);
    eval.set_sub_input_word(282, m31_9);
    eval.set_sub_input_word_u32(283, blake_round_output_round_8_tmp_40cd9_153.2 .0[0]);
    eval.set_sub_input_word_u32(284, blake_round_output_round_8_tmp_40cd9_153.2 .0[1]);
    eval.set_sub_input_word_u32(285, blake_round_output_round_8_tmp_40cd9_153.2 .0[2]);
    eval.set_sub_input_word_u32(286, blake_round_output_round_8_tmp_40cd9_153.2 .0[3]);
    eval.set_sub_input_word_u32(287, blake_round_output_round_8_tmp_40cd9_153.2 .0[4]);
    eval.set_sub_input_word_u32(288, blake_round_output_round_8_tmp_40cd9_153.2 .0[5]);
    eval.set_sub_input_word_u32(289, blake_round_output_round_8_tmp_40cd9_153.2 .0[6]);
    eval.set_sub_input_word_u32(290, blake_round_output_round_8_tmp_40cd9_153.2 .0[7]);
    eval.set_sub_input_word_u32(291, blake_round_output_round_8_tmp_40cd9_153.2 .0[8]);
    eval.set_sub_input_word_u32(292, blake_round_output_round_8_tmp_40cd9_153.2 .0[9]);
    eval.set_sub_input_word_u32(293, blake_round_output_round_8_tmp_40cd9_153.2 .0[10]);
    eval.set_sub_input_word_u32(294, blake_round_output_round_8_tmp_40cd9_153.2 .0[11]);
    eval.set_sub_input_word_u32(295, blake_round_output_round_8_tmp_40cd9_153.2 .0[12]);
    eval.set_sub_input_word_u32(296, blake_round_output_round_8_tmp_40cd9_153.2 .0[13]);
    eval.set_sub_input_word_u32(297, blake_round_output_round_8_tmp_40cd9_153.2 .0[14]);
    eval.set_sub_input_word_u32(298, blake_round_output_round_8_tmp_40cd9_153.2 .0[15]);
    eval.set_sub_input_word(299, blake_round_output_round_8_tmp_40cd9_153.2 .1);
    let blake_round_output_round_9_tmp_40cd9_154 = eval.deduce_blake_round(
        seq,
        m31_9,
        [
            blake_round_output_round_8_tmp_40cd9_153.2 .0[0],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[1],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[2],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[3],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[4],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[5],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[6],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[7],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[8],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[9],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[10],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[11],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[12],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[13],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[14],
            blake_round_output_round_8_tmp_40cd9_153.2 .0[15],
        ],
        blake_round_output_round_8_tmp_40cd9_153.2 .1,
    );
    let wg_v420 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[0]);
    let blake_round_output_limb_0_col92 = eval.u16_as_m31(wg_v420);
    eval.set_col(92, blake_round_output_limb_0_col92);
    let wg_v421 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[0]);
    let blake_round_output_limb_1_col93 = eval.u16_as_m31(wg_v421);
    eval.set_col(93, blake_round_output_limb_1_col93);
    let wg_v422 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[1]);
    let blake_round_output_limb_2_col94 = eval.u16_as_m31(wg_v422);
    eval.set_col(94, blake_round_output_limb_2_col94);
    let wg_v423 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[1]);
    let blake_round_output_limb_3_col95 = eval.u16_as_m31(wg_v423);
    eval.set_col(95, blake_round_output_limb_3_col95);
    let wg_v424 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[2]);
    let blake_round_output_limb_4_col96 = eval.u16_as_m31(wg_v424);
    eval.set_col(96, blake_round_output_limb_4_col96);
    let wg_v425 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[2]);
    let blake_round_output_limb_5_col97 = eval.u16_as_m31(wg_v425);
    eval.set_col(97, blake_round_output_limb_5_col97);
    let wg_v426 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[3]);
    let blake_round_output_limb_6_col98 = eval.u16_as_m31(wg_v426);
    eval.set_col(98, blake_round_output_limb_6_col98);
    let wg_v427 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[3]);
    let blake_round_output_limb_7_col99 = eval.u16_as_m31(wg_v427);
    eval.set_col(99, blake_round_output_limb_7_col99);
    let wg_v428 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[4]);
    let blake_round_output_limb_8_col100 = eval.u16_as_m31(wg_v428);
    eval.set_col(100, blake_round_output_limb_8_col100);
    let wg_v429 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[4]);
    let blake_round_output_limb_9_col101 = eval.u16_as_m31(wg_v429);
    eval.set_col(101, blake_round_output_limb_9_col101);
    let wg_v430 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[5]);
    let blake_round_output_limb_10_col102 = eval.u16_as_m31(wg_v430);
    eval.set_col(102, blake_round_output_limb_10_col102);
    let wg_v431 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[5]);
    let blake_round_output_limb_11_col103 = eval.u16_as_m31(wg_v431);
    eval.set_col(103, blake_round_output_limb_11_col103);
    let wg_v432 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[6]);
    let blake_round_output_limb_12_col104 = eval.u16_as_m31(wg_v432);
    eval.set_col(104, blake_round_output_limb_12_col104);
    let wg_v433 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[6]);
    let blake_round_output_limb_13_col105 = eval.u16_as_m31(wg_v433);
    eval.set_col(105, blake_round_output_limb_13_col105);
    let wg_v434 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[7]);
    let blake_round_output_limb_14_col106 = eval.u16_as_m31(wg_v434);
    eval.set_col(106, blake_round_output_limb_14_col106);
    let wg_v435 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[7]);
    let blake_round_output_limb_15_col107 = eval.u16_as_m31(wg_v435);
    eval.set_col(107, blake_round_output_limb_15_col107);
    let wg_v436 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[8]);
    let blake_round_output_limb_16_col108 = eval.u16_as_m31(wg_v436);
    eval.set_col(108, blake_round_output_limb_16_col108);
    let wg_v437 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[8]);
    let blake_round_output_limb_17_col109 = eval.u16_as_m31(wg_v437);
    eval.set_col(109, blake_round_output_limb_17_col109);
    let wg_v438 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[9]);
    let blake_round_output_limb_18_col110 = eval.u16_as_m31(wg_v438);
    eval.set_col(110, blake_round_output_limb_18_col110);
    let wg_v439 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[9]);
    let blake_round_output_limb_19_col111 = eval.u16_as_m31(wg_v439);
    eval.set_col(111, blake_round_output_limb_19_col111);
    let wg_v440 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[10]);
    let blake_round_output_limb_20_col112 = eval.u16_as_m31(wg_v440);
    eval.set_col(112, blake_round_output_limb_20_col112);
    let wg_v441 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[10]);
    let blake_round_output_limb_21_col113 = eval.u16_as_m31(wg_v441);
    eval.set_col(113, blake_round_output_limb_21_col113);
    let wg_v442 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[11]);
    let blake_round_output_limb_22_col114 = eval.u16_as_m31(wg_v442);
    eval.set_col(114, blake_round_output_limb_22_col114);
    let wg_v443 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[11]);
    let blake_round_output_limb_23_col115 = eval.u16_as_m31(wg_v443);
    eval.set_col(115, blake_round_output_limb_23_col115);
    let wg_v444 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[12]);
    let blake_round_output_limb_24_col116 = eval.u16_as_m31(wg_v444);
    eval.set_col(116, blake_round_output_limb_24_col116);
    let wg_v445 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[12]);
    let blake_round_output_limb_25_col117 = eval.u16_as_m31(wg_v445);
    eval.set_col(117, blake_round_output_limb_25_col117);
    let wg_v446 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[13]);
    let blake_round_output_limb_26_col118 = eval.u16_as_m31(wg_v446);
    eval.set_col(118, blake_round_output_limb_26_col118);
    let wg_v447 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[13]);
    let blake_round_output_limb_27_col119 = eval.u16_as_m31(wg_v447);
    eval.set_col(119, blake_round_output_limb_27_col119);
    let wg_v448 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[14]);
    let blake_round_output_limb_28_col120 = eval.u16_as_m31(wg_v448);
    eval.set_col(120, blake_round_output_limb_28_col120);
    let wg_v449 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[14]);
    let blake_round_output_limb_29_col121 = eval.u16_as_m31(wg_v449);
    eval.set_col(121, blake_round_output_limb_29_col121);
    let wg_v450 = eval.u32_low(blake_round_output_round_9_tmp_40cd9_154.2 .0[15]);
    let blake_round_output_limb_30_col122 = eval.u16_as_m31(wg_v450);
    eval.set_col(122, blake_round_output_limb_30_col122);
    let wg_v451 = eval.u32_high(blake_round_output_round_9_tmp_40cd9_154.2 .0[15]);
    let blake_round_output_limb_31_col123 = eval.u16_as_m31(wg_v451);
    eval.set_col(123, blake_round_output_limb_31_col123);
    let blake_round_output_limb_32_col124 = blake_round_output_round_9_tmp_40cd9_154.2 .1;
    eval.set_col(124, blake_round_output_limb_32_col124);
    eval.set_lookup_word(492, m31_40528774);
    eval.set_lookup_word(493, seq);
    eval.set_lookup_word(494, m31_10);
    eval.set_lookup_word(495, blake_round_output_limb_0_col92);
    eval.set_lookup_word(496, blake_round_output_limb_1_col93);
    eval.set_lookup_word(497, blake_round_output_limb_2_col94);
    eval.set_lookup_word(498, blake_round_output_limb_3_col95);
    eval.set_lookup_word(499, blake_round_output_limb_4_col96);
    eval.set_lookup_word(500, blake_round_output_limb_5_col97);
    eval.set_lookup_word(501, blake_round_output_limb_6_col98);
    eval.set_lookup_word(502, blake_round_output_limb_7_col99);
    eval.set_lookup_word(503, blake_round_output_limb_8_col100);
    eval.set_lookup_word(504, blake_round_output_limb_9_col101);
    eval.set_lookup_word(505, blake_round_output_limb_10_col102);
    eval.set_lookup_word(506, blake_round_output_limb_11_col103);
    eval.set_lookup_word(507, blake_round_output_limb_12_col104);
    eval.set_lookup_word(508, blake_round_output_limb_13_col105);
    eval.set_lookup_word(509, blake_round_output_limb_14_col106);
    eval.set_lookup_word(510, blake_round_output_limb_15_col107);
    eval.set_lookup_word(511, blake_round_output_limb_16_col108);
    eval.set_lookup_word(512, blake_round_output_limb_17_col109);
    eval.set_lookup_word(513, blake_round_output_limb_18_col110);
    eval.set_lookup_word(514, blake_round_output_limb_19_col111);
    eval.set_lookup_word(515, blake_round_output_limb_20_col112);
    eval.set_lookup_word(516, blake_round_output_limb_21_col113);
    eval.set_lookup_word(517, blake_round_output_limb_22_col114);
    eval.set_lookup_word(518, blake_round_output_limb_23_col115);
    eval.set_lookup_word(519, blake_round_output_limb_24_col116);
    eval.set_lookup_word(520, blake_round_output_limb_25_col117);
    eval.set_lookup_word(521, blake_round_output_limb_26_col118);
    eval.set_lookup_word(522, blake_round_output_limb_27_col119);
    eval.set_lookup_word(523, blake_round_output_limb_28_col120);
    eval.set_lookup_word(524, blake_round_output_limb_29_col121);
    eval.set_lookup_word(525, blake_round_output_limb_30_col122);
    eval.set_lookup_word(526, blake_round_output_limb_31_col123);
    eval.set_lookup_word(527, blake_round_output_limb_32_col124);
    eval.set_sub_input_word_u32(300, blake_round_output_round_9_tmp_40cd9_154.2 .0[0]);
    eval.set_sub_input_word_u32(301, blake_round_output_round_9_tmp_40cd9_154.2 .0[8]);
    eval.set_sub_input_word_u32(302, create_blake_round_input_output_tmp_40cd9_143[0]);
    let triple_xor_32_output_tmp_40cd9_155 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[0],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[8],
        create_blake_round_input_output_tmp_40cd9_143[0],
    ]);
    let wg_v452 = eval.u32_low(triple_xor_32_output_tmp_40cd9_155);
    let triple_xor_32_output_limb_0_col125 = eval.u16_as_m31(wg_v452);
    eval.set_col(125, triple_xor_32_output_limb_0_col125);
    let wg_v453 = eval.u32_high(triple_xor_32_output_tmp_40cd9_155);
    let triple_xor_32_output_limb_1_col126 = eval.u16_as_m31(wg_v453);
    eval.set_col(126, triple_xor_32_output_limb_1_col126);
    eval.set_lookup_word(528, m31_990559919);
    eval.set_lookup_word(529, blake_round_output_limb_0_col92);
    eval.set_lookup_word(530, blake_round_output_limb_1_col93);
    eval.set_lookup_word(531, blake_round_output_limb_16_col108);
    eval.set_lookup_word(532, blake_round_output_limb_17_col109);
    eval.set_lookup_word(533, low_16_bits_col38);
    eval.set_lookup_word(534, high_16_bits_col39);
    eval.set_lookup_word(535, triple_xor_32_output_limb_0_col125);
    eval.set_lookup_word(536, triple_xor_32_output_limb_1_col126);
    eval.set_sub_input_word_u32(303, blake_round_output_round_9_tmp_40cd9_154.2 .0[1]);
    eval.set_sub_input_word_u32(304, blake_round_output_round_9_tmp_40cd9_154.2 .0[9]);
    eval.set_sub_input_word_u32(305, create_blake_round_input_output_tmp_40cd9_143[1]);
    let triple_xor_32_output_tmp_40cd9_156 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[1],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[9],
        create_blake_round_input_output_tmp_40cd9_143[1],
    ]);
    let wg_v454 = eval.u32_low(triple_xor_32_output_tmp_40cd9_156);
    let triple_xor_32_output_limb_0_col127 = eval.u16_as_m31(wg_v454);
    eval.set_col(127, triple_xor_32_output_limb_0_col127);
    let wg_v455 = eval.u32_high(triple_xor_32_output_tmp_40cd9_156);
    let triple_xor_32_output_limb_1_col128 = eval.u16_as_m31(wg_v455);
    eval.set_col(128, triple_xor_32_output_limb_1_col128);
    eval.set_lookup_word(537, m31_990559919);
    eval.set_lookup_word(538, blake_round_output_limb_2_col94);
    eval.set_lookup_word(539, blake_round_output_limb_3_col95);
    eval.set_lookup_word(540, blake_round_output_limb_18_col110);
    eval.set_lookup_word(541, blake_round_output_limb_19_col111);
    eval.set_lookup_word(542, low_16_bits_col44);
    eval.set_lookup_word(543, high_16_bits_col45);
    eval.set_lookup_word(544, triple_xor_32_output_limb_0_col127);
    eval.set_lookup_word(545, triple_xor_32_output_limb_1_col128);
    eval.set_sub_input_word_u32(306, blake_round_output_round_9_tmp_40cd9_154.2 .0[2]);
    eval.set_sub_input_word_u32(307, blake_round_output_round_9_tmp_40cd9_154.2 .0[10]);
    eval.set_sub_input_word_u32(308, create_blake_round_input_output_tmp_40cd9_143[2]);
    let triple_xor_32_output_tmp_40cd9_157 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[2],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[10],
        create_blake_round_input_output_tmp_40cd9_143[2],
    ]);
    let wg_v456 = eval.u32_low(triple_xor_32_output_tmp_40cd9_157);
    let triple_xor_32_output_limb_0_col129 = eval.u16_as_m31(wg_v456);
    eval.set_col(129, triple_xor_32_output_limb_0_col129);
    let wg_v457 = eval.u32_high(triple_xor_32_output_tmp_40cd9_157);
    let triple_xor_32_output_limb_1_col130 = eval.u16_as_m31(wg_v457);
    eval.set_col(130, triple_xor_32_output_limb_1_col130);
    eval.set_lookup_word(546, m31_990559919);
    eval.set_lookup_word(547, blake_round_output_limb_4_col96);
    eval.set_lookup_word(548, blake_round_output_limb_5_col97);
    eval.set_lookup_word(549, blake_round_output_limb_20_col112);
    eval.set_lookup_word(550, blake_round_output_limb_21_col113);
    eval.set_lookup_word(551, low_16_bits_col50);
    eval.set_lookup_word(552, high_16_bits_col51);
    eval.set_lookup_word(553, triple_xor_32_output_limb_0_col129);
    eval.set_lookup_word(554, triple_xor_32_output_limb_1_col130);
    eval.set_sub_input_word_u32(309, blake_round_output_round_9_tmp_40cd9_154.2 .0[3]);
    eval.set_sub_input_word_u32(310, blake_round_output_round_9_tmp_40cd9_154.2 .0[11]);
    eval.set_sub_input_word_u32(311, create_blake_round_input_output_tmp_40cd9_143[3]);
    let triple_xor_32_output_tmp_40cd9_158 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[3],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[11],
        create_blake_round_input_output_tmp_40cd9_143[3],
    ]);
    let wg_v458 = eval.u32_low(triple_xor_32_output_tmp_40cd9_158);
    let triple_xor_32_output_limb_0_col131 = eval.u16_as_m31(wg_v458);
    eval.set_col(131, triple_xor_32_output_limb_0_col131);
    let wg_v459 = eval.u32_high(triple_xor_32_output_tmp_40cd9_158);
    let triple_xor_32_output_limb_1_col132 = eval.u16_as_m31(wg_v459);
    eval.set_col(132, triple_xor_32_output_limb_1_col132);
    eval.set_lookup_word(555, m31_990559919);
    eval.set_lookup_word(556, blake_round_output_limb_6_col98);
    eval.set_lookup_word(557, blake_round_output_limb_7_col99);
    eval.set_lookup_word(558, blake_round_output_limb_22_col114);
    eval.set_lookup_word(559, blake_round_output_limb_23_col115);
    eval.set_lookup_word(560, low_16_bits_col56);
    eval.set_lookup_word(561, high_16_bits_col57);
    eval.set_lookup_word(562, triple_xor_32_output_limb_0_col131);
    eval.set_lookup_word(563, triple_xor_32_output_limb_1_col132);
    eval.set_sub_input_word_u32(312, blake_round_output_round_9_tmp_40cd9_154.2 .0[4]);
    eval.set_sub_input_word_u32(313, blake_round_output_round_9_tmp_40cd9_154.2 .0[12]);
    eval.set_sub_input_word_u32(314, create_blake_round_input_output_tmp_40cd9_143[4]);
    let triple_xor_32_output_tmp_40cd9_159 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[4],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[12],
        create_blake_round_input_output_tmp_40cd9_143[4],
    ]);
    let wg_v460 = eval.u32_low(triple_xor_32_output_tmp_40cd9_159);
    let triple_xor_32_output_limb_0_col133 = eval.u16_as_m31(wg_v460);
    eval.set_col(133, triple_xor_32_output_limb_0_col133);
    let wg_v461 = eval.u32_high(triple_xor_32_output_tmp_40cd9_159);
    let triple_xor_32_output_limb_1_col134 = eval.u16_as_m31(wg_v461);
    eval.set_col(134, triple_xor_32_output_limb_1_col134);
    eval.set_lookup_word(564, m31_990559919);
    eval.set_lookup_word(565, blake_round_output_limb_8_col100);
    eval.set_lookup_word(566, blake_round_output_limb_9_col101);
    eval.set_lookup_word(567, blake_round_output_limb_24_col116);
    eval.set_lookup_word(568, blake_round_output_limb_25_col117);
    eval.set_lookup_word(569, low_16_bits_col62);
    eval.set_lookup_word(570, high_16_bits_col63);
    eval.set_lookup_word(571, triple_xor_32_output_limb_0_col133);
    eval.set_lookup_word(572, triple_xor_32_output_limb_1_col134);
    eval.set_sub_input_word_u32(315, blake_round_output_round_9_tmp_40cd9_154.2 .0[5]);
    eval.set_sub_input_word_u32(316, blake_round_output_round_9_tmp_40cd9_154.2 .0[13]);
    eval.set_sub_input_word_u32(317, create_blake_round_input_output_tmp_40cd9_143[5]);
    let triple_xor_32_output_tmp_40cd9_160 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[5],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[13],
        create_blake_round_input_output_tmp_40cd9_143[5],
    ]);
    let wg_v462 = eval.u32_low(triple_xor_32_output_tmp_40cd9_160);
    let triple_xor_32_output_limb_0_col135 = eval.u16_as_m31(wg_v462);
    eval.set_col(135, triple_xor_32_output_limb_0_col135);
    let wg_v463 = eval.u32_high(triple_xor_32_output_tmp_40cd9_160);
    let triple_xor_32_output_limb_1_col136 = eval.u16_as_m31(wg_v463);
    eval.set_col(136, triple_xor_32_output_limb_1_col136);
    eval.set_lookup_word(573, m31_990559919);
    eval.set_lookup_word(574, blake_round_output_limb_10_col102);
    eval.set_lookup_word(575, blake_round_output_limb_11_col103);
    eval.set_lookup_word(576, blake_round_output_limb_26_col118);
    eval.set_lookup_word(577, blake_round_output_limb_27_col119);
    eval.set_lookup_word(578, low_16_bits_col68);
    eval.set_lookup_word(579, high_16_bits_col69);
    eval.set_lookup_word(580, triple_xor_32_output_limb_0_col135);
    eval.set_lookup_word(581, triple_xor_32_output_limb_1_col136);
    eval.set_sub_input_word_u32(318, blake_round_output_round_9_tmp_40cd9_154.2 .0[6]);
    eval.set_sub_input_word_u32(319, blake_round_output_round_9_tmp_40cd9_154.2 .0[14]);
    eval.set_sub_input_word_u32(320, create_blake_round_input_output_tmp_40cd9_143[6]);
    let triple_xor_32_output_tmp_40cd9_161 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[6],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[14],
        create_blake_round_input_output_tmp_40cd9_143[6],
    ]);
    let wg_v464 = eval.u32_low(triple_xor_32_output_tmp_40cd9_161);
    let triple_xor_32_output_limb_0_col137 = eval.u16_as_m31(wg_v464);
    eval.set_col(137, triple_xor_32_output_limb_0_col137);
    let wg_v465 = eval.u32_high(triple_xor_32_output_tmp_40cd9_161);
    let triple_xor_32_output_limb_1_col138 = eval.u16_as_m31(wg_v465);
    eval.set_col(138, triple_xor_32_output_limb_1_col138);
    eval.set_lookup_word(582, m31_990559919);
    eval.set_lookup_word(583, blake_round_output_limb_12_col104);
    eval.set_lookup_word(584, blake_round_output_limb_13_col105);
    eval.set_lookup_word(585, blake_round_output_limb_28_col120);
    eval.set_lookup_word(586, blake_round_output_limb_29_col121);
    eval.set_lookup_word(587, low_16_bits_col74);
    eval.set_lookup_word(588, high_16_bits_col75);
    eval.set_lookup_word(589, triple_xor_32_output_limb_0_col137);
    eval.set_lookup_word(590, triple_xor_32_output_limb_1_col138);
    eval.set_sub_input_word_u32(321, blake_round_output_round_9_tmp_40cd9_154.2 .0[7]);
    eval.set_sub_input_word_u32(322, blake_round_output_round_9_tmp_40cd9_154.2 .0[15]);
    eval.set_sub_input_word_u32(323, create_blake_round_input_output_tmp_40cd9_143[7]);
    let triple_xor_32_output_tmp_40cd9_162 = eval.deduce_triple_xor_32([
        blake_round_output_round_9_tmp_40cd9_154.2 .0[7],
        blake_round_output_round_9_tmp_40cd9_154.2 .0[15],
        create_blake_round_input_output_tmp_40cd9_143[7],
    ]);
    let wg_v466 = eval.u32_low(triple_xor_32_output_tmp_40cd9_162);
    let triple_xor_32_output_limb_0_col139 = eval.u16_as_m31(wg_v466);
    eval.set_col(139, triple_xor_32_output_limb_0_col139);
    let wg_v467 = eval.u32_high(triple_xor_32_output_tmp_40cd9_162);
    let triple_xor_32_output_limb_1_col140 = eval.u16_as_m31(wg_v467);
    eval.set_col(140, triple_xor_32_output_limb_1_col140);
    eval.set_lookup_word(591, m31_990559919);
    eval.set_lookup_word(592, blake_round_output_limb_14_col106);
    eval.set_lookup_word(593, blake_round_output_limb_15_col107);
    eval.set_lookup_word(594, blake_round_output_limb_30_col122);
    eval.set_lookup_word(595, blake_round_output_limb_31_col123);
    eval.set_lookup_word(596, low_16_bits_col80);
    eval.set_lookup_word(597, high_16_bits_col81);
    eval.set_lookup_word(598, triple_xor_32_output_limb_0_col139);
    eval.set_lookup_word(599, triple_xor_32_output_limb_1_col140);
    let create_blake_output_output_tmp_40cd9_163 = [
        triple_xor_32_output_tmp_40cd9_155,
        triple_xor_32_output_tmp_40cd9_156,
        triple_xor_32_output_tmp_40cd9_157,
        triple_xor_32_output_tmp_40cd9_158,
        triple_xor_32_output_tmp_40cd9_159,
        triple_xor_32_output_tmp_40cd9_160,
        triple_xor_32_output_tmp_40cd9_161,
        triple_xor_32_output_tmp_40cd9_162,
    ];
    let wg_v468 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[0]);
    let low_7_ms_bits_tmp_40cd9_164 = eval.u16_shr(wg_v468, 9);
    let low_7_ms_bits_col141 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_164);
    eval.set_col(141, low_7_ms_bits_col141);
    let wg_v469 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[0]);
    let high_14_ms_bits_tmp_40cd9_165 = eval.u16_shr(wg_v469, 2);
    let high_14_ms_bits_col142 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_165);
    eval.set_col(142, high_14_ms_bits_col142);
    let wg_v470 = eval.m31_mul(high_14_ms_bits_col142, m31_4);
    let high_2_ls_bits_tmp_40cd9_166 = eval.m31_sub(triple_xor_32_output_limb_1_col126, wg_v470);
    let high_5_ms_bits_tmp_40cd9_167 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_165, 9);
    let high_5_ms_bits_col143 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_167);
    eval.set_col(143, high_5_ms_bits_col143);
    eval.set_sub_input_word(74, low_7_ms_bits_col141);
    eval.set_sub_input_word(75, high_2_ls_bits_tmp_40cd9_166);
    eval.set_sub_input_word(76, high_5_ms_bits_col143);
    eval.set_lookup_word(600, m31_371240602);
    eval.set_lookup_word(601, low_7_ms_bits_col141);
    eval.set_lookup_word(602, high_2_ls_bits_tmp_40cd9_166);
    eval.set_lookup_word(603, high_5_ms_bits_col143);
    let memory_address_to_id_value_tmp_40cd9_168 =
        eval.mem_addr_to_id(decode_blake_opcode_output_tmp_40cd9_42.0[2]);
    let new_state_0_id_col144 = memory_address_to_id_value_tmp_40cd9_168;
    eval.set_col(144, new_state_0_id_col144);
    eval.set_sub_input_word(19, decode_blake_opcode_output_tmp_40cd9_42.0[2]);
    eval.set_lookup_word(604, m31_1444891767);
    eval.set_lookup_word(605, decode_blake_opcode_output_tmp_40cd9_42.0[2]);
    eval.set_lookup_word(606, new_state_0_id_col144);
    eval.set_sub_input_word(39, new_state_0_id_col144);
    eval.set_lookup_word(607, m31_1662111297);
    eval.set_lookup_word(608, new_state_0_id_col144);
    let wg_v471 = eval.m31_mul(low_7_ms_bits_col141, m31_512);
    let wg_v472 = eval.m31_sub(triple_xor_32_output_limb_0_col125, wg_v471);
    eval.set_lookup_word(609, wg_v472);
    let wg_v473 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_166, m31_128);
    let wg_v474 = eval.m31_add(low_7_ms_bits_col141, wg_v473);
    eval.set_lookup_word(610, wg_v474);
    let wg_v475 = eval.m31_mul(high_5_ms_bits_col143, m31_512);
    let wg_v476 = eval.m31_sub(high_14_ms_bits_col142, wg_v475);
    eval.set_lookup_word(611, wg_v476);
    eval.set_lookup_word(612, high_5_ms_bits_col143);
    eval.set_lookup_word(613, m31_0);
    eval.set_lookup_word(614, m31_0);
    eval.set_lookup_word(615, m31_0);
    eval.set_lookup_word(616, m31_0);
    eval.set_lookup_word(617, m31_0);
    eval.set_lookup_word(618, m31_0);
    eval.set_lookup_word(619, m31_0);
    eval.set_lookup_word(620, m31_0);
    eval.set_lookup_word(621, m31_0);
    eval.set_lookup_word(622, m31_0);
    eval.set_lookup_word(623, m31_0);
    eval.set_lookup_word(624, m31_0);
    eval.set_lookup_word(625, m31_0);
    eval.set_lookup_word(626, m31_0);
    eval.set_lookup_word(627, m31_0);
    eval.set_lookup_word(628, m31_0);
    eval.set_lookup_word(629, m31_0);
    eval.set_lookup_word(630, m31_0);
    eval.set_lookup_word(631, m31_0);
    eval.set_lookup_word(632, m31_0);
    eval.set_lookup_word(633, m31_0);
    eval.set_lookup_word(634, m31_0);
    eval.set_lookup_word(635, m31_0);
    eval.set_lookup_word(636, m31_0);
    let wg_v477 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[1]);
    let low_7_ms_bits_tmp_40cd9_170 = eval.u16_shr(wg_v477, 9);
    let low_7_ms_bits_col145 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_170);
    eval.set_col(145, low_7_ms_bits_col145);
    let wg_v478 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[1]);
    let high_14_ms_bits_tmp_40cd9_171 = eval.u16_shr(wg_v478, 2);
    let high_14_ms_bits_col146 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_171);
    eval.set_col(146, high_14_ms_bits_col146);
    let wg_v479 = eval.m31_mul(high_14_ms_bits_col146, m31_4);
    let high_2_ls_bits_tmp_40cd9_172 = eval.m31_sub(triple_xor_32_output_limb_1_col128, wg_v479);
    let high_5_ms_bits_tmp_40cd9_173 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_171, 9);
    let high_5_ms_bits_col147 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_173);
    eval.set_col(147, high_5_ms_bits_col147);
    eval.set_sub_input_word(77, low_7_ms_bits_col145);
    eval.set_sub_input_word(78, high_2_ls_bits_tmp_40cd9_172);
    eval.set_sub_input_word(79, high_5_ms_bits_col147);
    eval.set_lookup_word(637, m31_371240602);
    eval.set_lookup_word(638, low_7_ms_bits_col145);
    eval.set_lookup_word(639, high_2_ls_bits_tmp_40cd9_172);
    eval.set_lookup_word(640, high_5_ms_bits_col147);
    let wg_v480 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_1);
    let memory_address_to_id_value_tmp_40cd9_174 = eval.mem_addr_to_id(wg_v480);
    let new_state_1_id_col148 = memory_address_to_id_value_tmp_40cd9_174;
    eval.set_col(148, new_state_1_id_col148);
    let wg_v481 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_1);
    eval.set_sub_input_word(20, wg_v481);
    eval.set_lookup_word(641, m31_1444891767);
    let wg_v482 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_1);
    eval.set_lookup_word(642, wg_v482);
    eval.set_lookup_word(643, new_state_1_id_col148);
    eval.set_sub_input_word(40, new_state_1_id_col148);
    eval.set_lookup_word(644, m31_1662111297);
    eval.set_lookup_word(645, new_state_1_id_col148);
    let wg_v483 = eval.m31_mul(low_7_ms_bits_col145, m31_512);
    let wg_v484 = eval.m31_sub(triple_xor_32_output_limb_0_col127, wg_v483);
    eval.set_lookup_word(646, wg_v484);
    let wg_v485 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_172, m31_128);
    let wg_v486 = eval.m31_add(low_7_ms_bits_col145, wg_v485);
    eval.set_lookup_word(647, wg_v486);
    let wg_v487 = eval.m31_mul(high_5_ms_bits_col147, m31_512);
    let wg_v488 = eval.m31_sub(high_14_ms_bits_col146, wg_v487);
    eval.set_lookup_word(648, wg_v488);
    eval.set_lookup_word(649, high_5_ms_bits_col147);
    eval.set_lookup_word(650, m31_0);
    eval.set_lookup_word(651, m31_0);
    eval.set_lookup_word(652, m31_0);
    eval.set_lookup_word(653, m31_0);
    eval.set_lookup_word(654, m31_0);
    eval.set_lookup_word(655, m31_0);
    eval.set_lookup_word(656, m31_0);
    eval.set_lookup_word(657, m31_0);
    eval.set_lookup_word(658, m31_0);
    eval.set_lookup_word(659, m31_0);
    eval.set_lookup_word(660, m31_0);
    eval.set_lookup_word(661, m31_0);
    eval.set_lookup_word(662, m31_0);
    eval.set_lookup_word(663, m31_0);
    eval.set_lookup_word(664, m31_0);
    eval.set_lookup_word(665, m31_0);
    eval.set_lookup_word(666, m31_0);
    eval.set_lookup_word(667, m31_0);
    eval.set_lookup_word(668, m31_0);
    eval.set_lookup_word(669, m31_0);
    eval.set_lookup_word(670, m31_0);
    eval.set_lookup_word(671, m31_0);
    eval.set_lookup_word(672, m31_0);
    eval.set_lookup_word(673, m31_0);
    let wg_v489 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[2]);
    let low_7_ms_bits_tmp_40cd9_176 = eval.u16_shr(wg_v489, 9);
    let low_7_ms_bits_col149 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_176);
    eval.set_col(149, low_7_ms_bits_col149);
    let wg_v490 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[2]);
    let high_14_ms_bits_tmp_40cd9_177 = eval.u16_shr(wg_v490, 2);
    let high_14_ms_bits_col150 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_177);
    eval.set_col(150, high_14_ms_bits_col150);
    let wg_v491 = eval.m31_mul(high_14_ms_bits_col150, m31_4);
    let high_2_ls_bits_tmp_40cd9_178 = eval.m31_sub(triple_xor_32_output_limb_1_col130, wg_v491);
    let high_5_ms_bits_tmp_40cd9_179 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_177, 9);
    let high_5_ms_bits_col151 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_179);
    eval.set_col(151, high_5_ms_bits_col151);
    eval.set_sub_input_word(80, low_7_ms_bits_col149);
    eval.set_sub_input_word(81, high_2_ls_bits_tmp_40cd9_178);
    eval.set_sub_input_word(82, high_5_ms_bits_col151);
    eval.set_lookup_word(674, m31_371240602);
    eval.set_lookup_word(675, low_7_ms_bits_col149);
    eval.set_lookup_word(676, high_2_ls_bits_tmp_40cd9_178);
    eval.set_lookup_word(677, high_5_ms_bits_col151);
    let wg_v492 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_2);
    let memory_address_to_id_value_tmp_40cd9_180 = eval.mem_addr_to_id(wg_v492);
    let new_state_2_id_col152 = memory_address_to_id_value_tmp_40cd9_180;
    eval.set_col(152, new_state_2_id_col152);
    let wg_v493 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_2);
    eval.set_sub_input_word(21, wg_v493);
    eval.set_lookup_word(678, m31_1444891767);
    let wg_v494 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_2);
    eval.set_lookup_word(679, wg_v494);
    eval.set_lookup_word(680, new_state_2_id_col152);
    eval.set_sub_input_word(41, new_state_2_id_col152);
    eval.set_lookup_word(681, m31_1662111297);
    eval.set_lookup_word(682, new_state_2_id_col152);
    let wg_v495 = eval.m31_mul(low_7_ms_bits_col149, m31_512);
    let wg_v496 = eval.m31_sub(triple_xor_32_output_limb_0_col129, wg_v495);
    eval.set_lookup_word(683, wg_v496);
    let wg_v497 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_178, m31_128);
    let wg_v498 = eval.m31_add(low_7_ms_bits_col149, wg_v497);
    eval.set_lookup_word(684, wg_v498);
    let wg_v499 = eval.m31_mul(high_5_ms_bits_col151, m31_512);
    let wg_v500 = eval.m31_sub(high_14_ms_bits_col150, wg_v499);
    eval.set_lookup_word(685, wg_v500);
    eval.set_lookup_word(686, high_5_ms_bits_col151);
    eval.set_lookup_word(687, m31_0);
    eval.set_lookup_word(688, m31_0);
    eval.set_lookup_word(689, m31_0);
    eval.set_lookup_word(690, m31_0);
    eval.set_lookup_word(691, m31_0);
    eval.set_lookup_word(692, m31_0);
    eval.set_lookup_word(693, m31_0);
    eval.set_lookup_word(694, m31_0);
    eval.set_lookup_word(695, m31_0);
    eval.set_lookup_word(696, m31_0);
    eval.set_lookup_word(697, m31_0);
    eval.set_lookup_word(698, m31_0);
    eval.set_lookup_word(699, m31_0);
    eval.set_lookup_word(700, m31_0);
    eval.set_lookup_word(701, m31_0);
    eval.set_lookup_word(702, m31_0);
    eval.set_lookup_word(703, m31_0);
    eval.set_lookup_word(704, m31_0);
    eval.set_lookup_word(705, m31_0);
    eval.set_lookup_word(706, m31_0);
    eval.set_lookup_word(707, m31_0);
    eval.set_lookup_word(708, m31_0);
    eval.set_lookup_word(709, m31_0);
    eval.set_lookup_word(710, m31_0);
    let wg_v501 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[3]);
    let low_7_ms_bits_tmp_40cd9_182 = eval.u16_shr(wg_v501, 9);
    let low_7_ms_bits_col153 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_182);
    eval.set_col(153, low_7_ms_bits_col153);
    let wg_v502 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[3]);
    let high_14_ms_bits_tmp_40cd9_183 = eval.u16_shr(wg_v502, 2);
    let high_14_ms_bits_col154 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_183);
    eval.set_col(154, high_14_ms_bits_col154);
    let wg_v503 = eval.m31_mul(high_14_ms_bits_col154, m31_4);
    let high_2_ls_bits_tmp_40cd9_184 = eval.m31_sub(triple_xor_32_output_limb_1_col132, wg_v503);
    let high_5_ms_bits_tmp_40cd9_185 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_183, 9);
    let high_5_ms_bits_col155 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_185);
    eval.set_col(155, high_5_ms_bits_col155);
    eval.set_sub_input_word(83, low_7_ms_bits_col153);
    eval.set_sub_input_word(84, high_2_ls_bits_tmp_40cd9_184);
    eval.set_sub_input_word(85, high_5_ms_bits_col155);
    eval.set_lookup_word(711, m31_371240602);
    eval.set_lookup_word(712, low_7_ms_bits_col153);
    eval.set_lookup_word(713, high_2_ls_bits_tmp_40cd9_184);
    eval.set_lookup_word(714, high_5_ms_bits_col155);
    let wg_v504 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_3);
    let memory_address_to_id_value_tmp_40cd9_186 = eval.mem_addr_to_id(wg_v504);
    let new_state_3_id_col156 = memory_address_to_id_value_tmp_40cd9_186;
    eval.set_col(156, new_state_3_id_col156);
    let wg_v505 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_3);
    eval.set_sub_input_word(22, wg_v505);
    eval.set_lookup_word(715, m31_1444891767);
    let wg_v506 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_3);
    eval.set_lookup_word(716, wg_v506);
    eval.set_lookup_word(717, new_state_3_id_col156);
    eval.set_sub_input_word(42, new_state_3_id_col156);
    eval.set_lookup_word(718, m31_1662111297);
    eval.set_lookup_word(719, new_state_3_id_col156);
    let wg_v507 = eval.m31_mul(low_7_ms_bits_col153, m31_512);
    let wg_v508 = eval.m31_sub(triple_xor_32_output_limb_0_col131, wg_v507);
    eval.set_lookup_word(720, wg_v508);
    let wg_v509 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_184, m31_128);
    let wg_v510 = eval.m31_add(low_7_ms_bits_col153, wg_v509);
    eval.set_lookup_word(721, wg_v510);
    let wg_v511 = eval.m31_mul(high_5_ms_bits_col155, m31_512);
    let wg_v512 = eval.m31_sub(high_14_ms_bits_col154, wg_v511);
    eval.set_lookup_word(722, wg_v512);
    eval.set_lookup_word(723, high_5_ms_bits_col155);
    eval.set_lookup_word(724, m31_0);
    eval.set_lookup_word(725, m31_0);
    eval.set_lookup_word(726, m31_0);
    eval.set_lookup_word(727, m31_0);
    eval.set_lookup_word(728, m31_0);
    eval.set_lookup_word(729, m31_0);
    eval.set_lookup_word(730, m31_0);
    eval.set_lookup_word(731, m31_0);
    eval.set_lookup_word(732, m31_0);
    eval.set_lookup_word(733, m31_0);
    eval.set_lookup_word(734, m31_0);
    eval.set_lookup_word(735, m31_0);
    eval.set_lookup_word(736, m31_0);
    eval.set_lookup_word(737, m31_0);
    eval.set_lookup_word(738, m31_0);
    eval.set_lookup_word(739, m31_0);
    eval.set_lookup_word(740, m31_0);
    eval.set_lookup_word(741, m31_0);
    eval.set_lookup_word(742, m31_0);
    eval.set_lookup_word(743, m31_0);
    eval.set_lookup_word(744, m31_0);
    eval.set_lookup_word(745, m31_0);
    eval.set_lookup_word(746, m31_0);
    eval.set_lookup_word(747, m31_0);
    let wg_v513 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[4]);
    let low_7_ms_bits_tmp_40cd9_188 = eval.u16_shr(wg_v513, 9);
    let low_7_ms_bits_col157 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_188);
    eval.set_col(157, low_7_ms_bits_col157);
    let wg_v514 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[4]);
    let high_14_ms_bits_tmp_40cd9_189 = eval.u16_shr(wg_v514, 2);
    let high_14_ms_bits_col158 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_189);
    eval.set_col(158, high_14_ms_bits_col158);
    let wg_v515 = eval.m31_mul(high_14_ms_bits_col158, m31_4);
    let high_2_ls_bits_tmp_40cd9_190 = eval.m31_sub(triple_xor_32_output_limb_1_col134, wg_v515);
    let high_5_ms_bits_tmp_40cd9_191 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_189, 9);
    let high_5_ms_bits_col159 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_191);
    eval.set_col(159, high_5_ms_bits_col159);
    eval.set_sub_input_word(86, low_7_ms_bits_col157);
    eval.set_sub_input_word(87, high_2_ls_bits_tmp_40cd9_190);
    eval.set_sub_input_word(88, high_5_ms_bits_col159);
    eval.set_lookup_word(748, m31_371240602);
    eval.set_lookup_word(749, low_7_ms_bits_col157);
    eval.set_lookup_word(750, high_2_ls_bits_tmp_40cd9_190);
    eval.set_lookup_word(751, high_5_ms_bits_col159);
    let wg_v516 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_4);
    let memory_address_to_id_value_tmp_40cd9_192 = eval.mem_addr_to_id(wg_v516);
    let new_state_4_id_col160 = memory_address_to_id_value_tmp_40cd9_192;
    eval.set_col(160, new_state_4_id_col160);
    let wg_v517 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_4);
    eval.set_sub_input_word(23, wg_v517);
    eval.set_lookup_word(752, m31_1444891767);
    let wg_v518 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_4);
    eval.set_lookup_word(753, wg_v518);
    eval.set_lookup_word(754, new_state_4_id_col160);
    eval.set_sub_input_word(43, new_state_4_id_col160);
    eval.set_lookup_word(755, m31_1662111297);
    eval.set_lookup_word(756, new_state_4_id_col160);
    let wg_v519 = eval.m31_mul(low_7_ms_bits_col157, m31_512);
    let wg_v520 = eval.m31_sub(triple_xor_32_output_limb_0_col133, wg_v519);
    eval.set_lookup_word(757, wg_v520);
    let wg_v521 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_190, m31_128);
    let wg_v522 = eval.m31_add(low_7_ms_bits_col157, wg_v521);
    eval.set_lookup_word(758, wg_v522);
    let wg_v523 = eval.m31_mul(high_5_ms_bits_col159, m31_512);
    let wg_v524 = eval.m31_sub(high_14_ms_bits_col158, wg_v523);
    eval.set_lookup_word(759, wg_v524);
    eval.set_lookup_word(760, high_5_ms_bits_col159);
    eval.set_lookup_word(761, m31_0);
    eval.set_lookup_word(762, m31_0);
    eval.set_lookup_word(763, m31_0);
    eval.set_lookup_word(764, m31_0);
    eval.set_lookup_word(765, m31_0);
    eval.set_lookup_word(766, m31_0);
    eval.set_lookup_word(767, m31_0);
    eval.set_lookup_word(768, m31_0);
    eval.set_lookup_word(769, m31_0);
    eval.set_lookup_word(770, m31_0);
    eval.set_lookup_word(771, m31_0);
    eval.set_lookup_word(772, m31_0);
    eval.set_lookup_word(773, m31_0);
    eval.set_lookup_word(774, m31_0);
    eval.set_lookup_word(775, m31_0);
    eval.set_lookup_word(776, m31_0);
    eval.set_lookup_word(777, m31_0);
    eval.set_lookup_word(778, m31_0);
    eval.set_lookup_word(779, m31_0);
    eval.set_lookup_word(780, m31_0);
    eval.set_lookup_word(781, m31_0);
    eval.set_lookup_word(782, m31_0);
    eval.set_lookup_word(783, m31_0);
    eval.set_lookup_word(784, m31_0);
    let wg_v525 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[5]);
    let low_7_ms_bits_tmp_40cd9_194 = eval.u16_shr(wg_v525, 9);
    let low_7_ms_bits_col161 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_194);
    eval.set_col(161, low_7_ms_bits_col161);
    let wg_v526 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[5]);
    let high_14_ms_bits_tmp_40cd9_195 = eval.u16_shr(wg_v526, 2);
    let high_14_ms_bits_col162 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_195);
    eval.set_col(162, high_14_ms_bits_col162);
    let wg_v527 = eval.m31_mul(high_14_ms_bits_col162, m31_4);
    let high_2_ls_bits_tmp_40cd9_196 = eval.m31_sub(triple_xor_32_output_limb_1_col136, wg_v527);
    let high_5_ms_bits_tmp_40cd9_197 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_195, 9);
    let high_5_ms_bits_col163 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_197);
    eval.set_col(163, high_5_ms_bits_col163);
    eval.set_sub_input_word(89, low_7_ms_bits_col161);
    eval.set_sub_input_word(90, high_2_ls_bits_tmp_40cd9_196);
    eval.set_sub_input_word(91, high_5_ms_bits_col163);
    eval.set_lookup_word(785, m31_371240602);
    eval.set_lookup_word(786, low_7_ms_bits_col161);
    eval.set_lookup_word(787, high_2_ls_bits_tmp_40cd9_196);
    eval.set_lookup_word(788, high_5_ms_bits_col163);
    let wg_v528 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_5);
    let memory_address_to_id_value_tmp_40cd9_198 = eval.mem_addr_to_id(wg_v528);
    let new_state_5_id_col164 = memory_address_to_id_value_tmp_40cd9_198;
    eval.set_col(164, new_state_5_id_col164);
    let wg_v529 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_5);
    eval.set_sub_input_word(24, wg_v529);
    eval.set_lookup_word(789, m31_1444891767);
    let wg_v530 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_5);
    eval.set_lookup_word(790, wg_v530);
    eval.set_lookup_word(791, new_state_5_id_col164);
    eval.set_sub_input_word(44, new_state_5_id_col164);
    eval.set_lookup_word(792, m31_1662111297);
    eval.set_lookup_word(793, new_state_5_id_col164);
    let wg_v531 = eval.m31_mul(low_7_ms_bits_col161, m31_512);
    let wg_v532 = eval.m31_sub(triple_xor_32_output_limb_0_col135, wg_v531);
    eval.set_lookup_word(794, wg_v532);
    let wg_v533 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_196, m31_128);
    let wg_v534 = eval.m31_add(low_7_ms_bits_col161, wg_v533);
    eval.set_lookup_word(795, wg_v534);
    let wg_v535 = eval.m31_mul(high_5_ms_bits_col163, m31_512);
    let wg_v536 = eval.m31_sub(high_14_ms_bits_col162, wg_v535);
    eval.set_lookup_word(796, wg_v536);
    eval.set_lookup_word(797, high_5_ms_bits_col163);
    eval.set_lookup_word(798, m31_0);
    eval.set_lookup_word(799, m31_0);
    eval.set_lookup_word(800, m31_0);
    eval.set_lookup_word(801, m31_0);
    eval.set_lookup_word(802, m31_0);
    eval.set_lookup_word(803, m31_0);
    eval.set_lookup_word(804, m31_0);
    eval.set_lookup_word(805, m31_0);
    eval.set_lookup_word(806, m31_0);
    eval.set_lookup_word(807, m31_0);
    eval.set_lookup_word(808, m31_0);
    eval.set_lookup_word(809, m31_0);
    eval.set_lookup_word(810, m31_0);
    eval.set_lookup_word(811, m31_0);
    eval.set_lookup_word(812, m31_0);
    eval.set_lookup_word(813, m31_0);
    eval.set_lookup_word(814, m31_0);
    eval.set_lookup_word(815, m31_0);
    eval.set_lookup_word(816, m31_0);
    eval.set_lookup_word(817, m31_0);
    eval.set_lookup_word(818, m31_0);
    eval.set_lookup_word(819, m31_0);
    eval.set_lookup_word(820, m31_0);
    eval.set_lookup_word(821, m31_0);
    let wg_v537 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[6]);
    let low_7_ms_bits_tmp_40cd9_200 = eval.u16_shr(wg_v537, 9);
    let low_7_ms_bits_col165 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_200);
    eval.set_col(165, low_7_ms_bits_col165);
    let wg_v538 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[6]);
    let high_14_ms_bits_tmp_40cd9_201 = eval.u16_shr(wg_v538, 2);
    let high_14_ms_bits_col166 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_201);
    eval.set_col(166, high_14_ms_bits_col166);
    let wg_v539 = eval.m31_mul(high_14_ms_bits_col166, m31_4);
    let high_2_ls_bits_tmp_40cd9_202 = eval.m31_sub(triple_xor_32_output_limb_1_col138, wg_v539);
    let high_5_ms_bits_tmp_40cd9_203 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_201, 9);
    let high_5_ms_bits_col167 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_203);
    eval.set_col(167, high_5_ms_bits_col167);
    eval.set_sub_input_word(92, low_7_ms_bits_col165);
    eval.set_sub_input_word(93, high_2_ls_bits_tmp_40cd9_202);
    eval.set_sub_input_word(94, high_5_ms_bits_col167);
    eval.set_lookup_word(822, m31_371240602);
    eval.set_lookup_word(823, low_7_ms_bits_col165);
    eval.set_lookup_word(824, high_2_ls_bits_tmp_40cd9_202);
    eval.set_lookup_word(825, high_5_ms_bits_col167);
    let wg_v540 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_6);
    let memory_address_to_id_value_tmp_40cd9_204 = eval.mem_addr_to_id(wg_v540);
    let new_state_6_id_col168 = memory_address_to_id_value_tmp_40cd9_204;
    eval.set_col(168, new_state_6_id_col168);
    let wg_v541 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_6);
    eval.set_sub_input_word(25, wg_v541);
    eval.set_lookup_word(826, m31_1444891767);
    let wg_v542 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_6);
    eval.set_lookup_word(827, wg_v542);
    eval.set_lookup_word(828, new_state_6_id_col168);
    eval.set_sub_input_word(45, new_state_6_id_col168);
    eval.set_lookup_word(829, m31_1662111297);
    eval.set_lookup_word(830, new_state_6_id_col168);
    let wg_v543 = eval.m31_mul(low_7_ms_bits_col165, m31_512);
    let wg_v544 = eval.m31_sub(triple_xor_32_output_limb_0_col137, wg_v543);
    eval.set_lookup_word(831, wg_v544);
    let wg_v545 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_202, m31_128);
    let wg_v546 = eval.m31_add(low_7_ms_bits_col165, wg_v545);
    eval.set_lookup_word(832, wg_v546);
    let wg_v547 = eval.m31_mul(high_5_ms_bits_col167, m31_512);
    let wg_v548 = eval.m31_sub(high_14_ms_bits_col166, wg_v547);
    eval.set_lookup_word(833, wg_v548);
    eval.set_lookup_word(834, high_5_ms_bits_col167);
    eval.set_lookup_word(835, m31_0);
    eval.set_lookup_word(836, m31_0);
    eval.set_lookup_word(837, m31_0);
    eval.set_lookup_word(838, m31_0);
    eval.set_lookup_word(839, m31_0);
    eval.set_lookup_word(840, m31_0);
    eval.set_lookup_word(841, m31_0);
    eval.set_lookup_word(842, m31_0);
    eval.set_lookup_word(843, m31_0);
    eval.set_lookup_word(844, m31_0);
    eval.set_lookup_word(845, m31_0);
    eval.set_lookup_word(846, m31_0);
    eval.set_lookup_word(847, m31_0);
    eval.set_lookup_word(848, m31_0);
    eval.set_lookup_word(849, m31_0);
    eval.set_lookup_word(850, m31_0);
    eval.set_lookup_word(851, m31_0);
    eval.set_lookup_word(852, m31_0);
    eval.set_lookup_word(853, m31_0);
    eval.set_lookup_word(854, m31_0);
    eval.set_lookup_word(855, m31_0);
    eval.set_lookup_word(856, m31_0);
    eval.set_lookup_word(857, m31_0);
    eval.set_lookup_word(858, m31_0);
    let wg_v549 = eval.u32_low(create_blake_output_output_tmp_40cd9_163[7]);
    let low_7_ms_bits_tmp_40cd9_206 = eval.u16_shr(wg_v549, 9);
    let low_7_ms_bits_col169 = eval.u16_as_m31(low_7_ms_bits_tmp_40cd9_206);
    eval.set_col(169, low_7_ms_bits_col169);
    let wg_v550 = eval.u32_high(create_blake_output_output_tmp_40cd9_163[7]);
    let high_14_ms_bits_tmp_40cd9_207 = eval.u16_shr(wg_v550, 2);
    let high_14_ms_bits_col170 = eval.u16_as_m31(high_14_ms_bits_tmp_40cd9_207);
    eval.set_col(170, high_14_ms_bits_col170);
    let wg_v551 = eval.m31_mul(high_14_ms_bits_col170, m31_4);
    let high_2_ls_bits_tmp_40cd9_208 = eval.m31_sub(triple_xor_32_output_limb_1_col140, wg_v551);
    let high_5_ms_bits_tmp_40cd9_209 = eval.u16_shr(high_14_ms_bits_tmp_40cd9_207, 9);
    let high_5_ms_bits_col171 = eval.u16_as_m31(high_5_ms_bits_tmp_40cd9_209);
    eval.set_col(171, high_5_ms_bits_col171);
    eval.set_sub_input_word(95, low_7_ms_bits_col169);
    eval.set_sub_input_word(96, high_2_ls_bits_tmp_40cd9_208);
    eval.set_sub_input_word(97, high_5_ms_bits_col171);
    eval.set_lookup_word(859, m31_371240602);
    eval.set_lookup_word(860, low_7_ms_bits_col169);
    eval.set_lookup_word(861, high_2_ls_bits_tmp_40cd9_208);
    eval.set_lookup_word(862, high_5_ms_bits_col171);
    let wg_v552 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_7);
    let memory_address_to_id_value_tmp_40cd9_210 = eval.mem_addr_to_id(wg_v552);
    let new_state_7_id_col172 = memory_address_to_id_value_tmp_40cd9_210;
    eval.set_col(172, new_state_7_id_col172);
    let wg_v553 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_7);
    eval.set_sub_input_word(26, wg_v553);
    eval.set_lookup_word(863, m31_1444891767);
    let wg_v554 = eval.m31_add(decode_blake_opcode_output_tmp_40cd9_42.0[2], m31_7);
    eval.set_lookup_word(864, wg_v554);
    eval.set_lookup_word(865, new_state_7_id_col172);
    eval.set_sub_input_word(46, new_state_7_id_col172);
    eval.set_lookup_word(866, m31_1662111297);
    eval.set_lookup_word(867, new_state_7_id_col172);
    let wg_v555 = eval.m31_mul(low_7_ms_bits_col169, m31_512);
    let wg_v556 = eval.m31_sub(triple_xor_32_output_limb_0_col139, wg_v555);
    eval.set_lookup_word(868, wg_v556);
    let wg_v557 = eval.m31_mul(high_2_ls_bits_tmp_40cd9_208, m31_128);
    let wg_v558 = eval.m31_add(low_7_ms_bits_col169, wg_v557);
    eval.set_lookup_word(869, wg_v558);
    let wg_v559 = eval.m31_mul(high_5_ms_bits_col171, m31_512);
    let wg_v560 = eval.m31_sub(high_14_ms_bits_col170, wg_v559);
    eval.set_lookup_word(870, wg_v560);
    eval.set_lookup_word(871, high_5_ms_bits_col171);
    eval.set_lookup_word(872, m31_0);
    eval.set_lookup_word(873, m31_0);
    eval.set_lookup_word(874, m31_0);
    eval.set_lookup_word(875, m31_0);
    eval.set_lookup_word(876, m31_0);
    eval.set_lookup_word(877, m31_0);
    eval.set_lookup_word(878, m31_0);
    eval.set_lookup_word(879, m31_0);
    eval.set_lookup_word(880, m31_0);
    eval.set_lookup_word(881, m31_0);
    eval.set_lookup_word(882, m31_0);
    eval.set_lookup_word(883, m31_0);
    eval.set_lookup_word(884, m31_0);
    eval.set_lookup_word(885, m31_0);
    eval.set_lookup_word(886, m31_0);
    eval.set_lookup_word(887, m31_0);
    eval.set_lookup_word(888, m31_0);
    eval.set_lookup_word(889, m31_0);
    eval.set_lookup_word(890, m31_0);
    eval.set_lookup_word(891, m31_0);
    eval.set_lookup_word(892, m31_0);
    eval.set_lookup_word(893, m31_0);
    eval.set_lookup_word(894, m31_0);
    eval.set_lookup_word(895, m31_0);
    let enabler_col173 = eval.enabler();
    eval.set_col(173, enabler_col173);
    eval.set_lookup_word(896, m31_428564188);
    eval.set_lookup_word(897, input_pc_col0);
    eval.set_lookup_word(898, input_ap_col1);
    eval.set_lookup_word(899, input_fp_col2);
    eval.set_lookup_word(900, m31_428564188);
    let wg_v561 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_lookup_word(901, wg_v561);
    let wg_v562 = eval.m31_add(input_ap_col1, ap_update_add_1_col9);
    eval.set_lookup_word(902, wg_v562);
    eval.set_lookup_word(903, input_fp_col2);
    eval.set_lookup_word(904, m31_1);
    eval.set_lookup_word(905, enabler_col173);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `blake_compress_opcode_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
    blake_round_state: &blake_round::ClaimGenerator,
    triple_xor_32_state: &triple_xor_32::ClaimGenerator,
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
    let seq = Seq::new(log_size);
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
            |(row_index, (row, lookup_data, sub_component_inputs, blake_compress_opcode_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    blake_compress_opcode_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                blake_compress_opcode_row_body(&mut eval);
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
                *lookup_data.range_check_7_2_5_7 = [lw[107], lw[108], lw[109], lw[110]];
                *lookup_data.memory_address_to_id_8 = [lw[111], lw[112], lw[113]];
                *lookup_data.memory_id_to_big_9 = [
                    lw[114], lw[115], lw[116], lw[117], lw[118], lw[119], lw[120], lw[121],
                    lw[122], lw[123], lw[124], lw[125], lw[126], lw[127], lw[128], lw[129],
                    lw[130], lw[131], lw[132], lw[133], lw[134], lw[135], lw[136], lw[137],
                    lw[138], lw[139], lw[140], lw[141], lw[142], lw[143],
                ];
                *lookup_data.range_check_7_2_5_10 = [lw[144], lw[145], lw[146], lw[147]];
                *lookup_data.memory_address_to_id_11 = [lw[148], lw[149], lw[150]];
                *lookup_data.memory_id_to_big_12 = [
                    lw[151], lw[152], lw[153], lw[154], lw[155], lw[156], lw[157], lw[158],
                    lw[159], lw[160], lw[161], lw[162], lw[163], lw[164], lw[165], lw[166],
                    lw[167], lw[168], lw[169], lw[170], lw[171], lw[172], lw[173], lw[174],
                    lw[175], lw[176], lw[177], lw[178], lw[179], lw[180],
                ];
                *lookup_data.range_check_7_2_5_13 = [lw[181], lw[182], lw[183], lw[184]];
                *lookup_data.memory_address_to_id_14 = [lw[185], lw[186], lw[187]];
                *lookup_data.memory_id_to_big_15 = [
                    lw[188], lw[189], lw[190], lw[191], lw[192], lw[193], lw[194], lw[195],
                    lw[196], lw[197], lw[198], lw[199], lw[200], lw[201], lw[202], lw[203],
                    lw[204], lw[205], lw[206], lw[207], lw[208], lw[209], lw[210], lw[211],
                    lw[212], lw[213], lw[214], lw[215], lw[216], lw[217],
                ];
                *lookup_data.range_check_7_2_5_16 = [lw[218], lw[219], lw[220], lw[221]];
                *lookup_data.memory_address_to_id_17 = [lw[222], lw[223], lw[224]];
                *lookup_data.memory_id_to_big_18 = [
                    lw[225], lw[226], lw[227], lw[228], lw[229], lw[230], lw[231], lw[232],
                    lw[233], lw[234], lw[235], lw[236], lw[237], lw[238], lw[239], lw[240],
                    lw[241], lw[242], lw[243], lw[244], lw[245], lw[246], lw[247], lw[248],
                    lw[249], lw[250], lw[251], lw[252], lw[253], lw[254],
                ];
                *lookup_data.range_check_7_2_5_19 = [lw[255], lw[256], lw[257], lw[258]];
                *lookup_data.memory_address_to_id_20 = [lw[259], lw[260], lw[261]];
                *lookup_data.memory_id_to_big_21 = [
                    lw[262], lw[263], lw[264], lw[265], lw[266], lw[267], lw[268], lw[269],
                    lw[270], lw[271], lw[272], lw[273], lw[274], lw[275], lw[276], lw[277],
                    lw[278], lw[279], lw[280], lw[281], lw[282], lw[283], lw[284], lw[285],
                    lw[286], lw[287], lw[288], lw[289], lw[290], lw[291],
                ];
                *lookup_data.range_check_7_2_5_22 = [lw[292], lw[293], lw[294], lw[295]];
                *lookup_data.memory_address_to_id_23 = [lw[296], lw[297], lw[298]];
                *lookup_data.memory_id_to_big_24 = [
                    lw[299], lw[300], lw[301], lw[302], lw[303], lw[304], lw[305], lw[306],
                    lw[307], lw[308], lw[309], lw[310], lw[311], lw[312], lw[313], lw[314],
                    lw[315], lw[316], lw[317], lw[318], lw[319], lw[320], lw[321], lw[322],
                    lw[323], lw[324], lw[325], lw[326], lw[327], lw[328],
                ];
                *lookup_data.range_check_7_2_5_25 = [lw[329], lw[330], lw[331], lw[332]];
                *lookup_data.memory_address_to_id_26 = [lw[333], lw[334], lw[335]];
                *lookup_data.memory_id_to_big_27 = [
                    lw[336], lw[337], lw[338], lw[339], lw[340], lw[341], lw[342], lw[343],
                    lw[344], lw[345], lw[346], lw[347], lw[348], lw[349], lw[350], lw[351],
                    lw[352], lw[353], lw[354], lw[355], lw[356], lw[357], lw[358], lw[359],
                    lw[360], lw[361], lw[362], lw[363], lw[364], lw[365],
                ];
                *lookup_data.range_check_7_2_5_28 = [lw[366], lw[367], lw[368], lw[369]];
                *lookup_data.memory_address_to_id_29 = [lw[370], lw[371], lw[372]];
                *lookup_data.memory_id_to_big_30 = [
                    lw[373], lw[374], lw[375], lw[376], lw[377], lw[378], lw[379], lw[380],
                    lw[381], lw[382], lw[383], lw[384], lw[385], lw[386], lw[387], lw[388],
                    lw[389], lw[390], lw[391], lw[392], lw[393], lw[394], lw[395], lw[396],
                    lw[397], lw[398], lw[399], lw[400], lw[401], lw[402],
                ];
                *lookup_data.range_check_7_2_5_31 = [lw[403], lw[404], lw[405], lw[406]];
                *lookup_data.memory_address_to_id_32 = [lw[407], lw[408], lw[409]];
                *lookup_data.memory_id_to_big_33 = [
                    lw[410], lw[411], lw[412], lw[413], lw[414], lw[415], lw[416], lw[417],
                    lw[418], lw[419], lw[420], lw[421], lw[422], lw[423], lw[424], lw[425],
                    lw[426], lw[427], lw[428], lw[429], lw[430], lw[431], lw[432], lw[433],
                    lw[434], lw[435], lw[436], lw[437], lw[438], lw[439],
                ];
                *lookup_data.verify_bitwise_xor_8_34 = [lw[440], lw[441], lw[442], lw[443]];
                *lookup_data.verify_bitwise_xor_8_35 = [lw[444], lw[445], lw[446], lw[447]];
                *lookup_data.verify_bitwise_xor_8_36 = [lw[448], lw[449], lw[450], lw[451]];
                *lookup_data.verify_bitwise_xor_8_37 = [lw[452], lw[453], lw[454], lw[455]];
                *lookup_data.blake_round_38 = [
                    lw[456], lw[457], lw[458], lw[459], lw[460], lw[461], lw[462], lw[463],
                    lw[464], lw[465], lw[466], lw[467], lw[468], lw[469], lw[470], lw[471],
                    lw[472], lw[473], lw[474], lw[475], lw[476], lw[477], lw[478], lw[479],
                    lw[480], lw[481], lw[482], lw[483], lw[484], lw[485], lw[486], lw[487],
                    lw[488], lw[489], lw[490], lw[491],
                ];
                *lookup_data.blake_round_39 = [
                    lw[492], lw[493], lw[494], lw[495], lw[496], lw[497], lw[498], lw[499],
                    lw[500], lw[501], lw[502], lw[503], lw[504], lw[505], lw[506], lw[507],
                    lw[508], lw[509], lw[510], lw[511], lw[512], lw[513], lw[514], lw[515],
                    lw[516], lw[517], lw[518], lw[519], lw[520], lw[521], lw[522], lw[523],
                    lw[524], lw[525], lw[526], lw[527],
                ];
                *lookup_data.triple_xor_32_40 = [
                    lw[528], lw[529], lw[530], lw[531], lw[532], lw[533], lw[534], lw[535], lw[536],
                ];
                *lookup_data.triple_xor_32_41 = [
                    lw[537], lw[538], lw[539], lw[540], lw[541], lw[542], lw[543], lw[544], lw[545],
                ];
                *lookup_data.triple_xor_32_42 = [
                    lw[546], lw[547], lw[548], lw[549], lw[550], lw[551], lw[552], lw[553], lw[554],
                ];
                *lookup_data.triple_xor_32_43 = [
                    lw[555], lw[556], lw[557], lw[558], lw[559], lw[560], lw[561], lw[562], lw[563],
                ];
                *lookup_data.triple_xor_32_44 = [
                    lw[564], lw[565], lw[566], lw[567], lw[568], lw[569], lw[570], lw[571], lw[572],
                ];
                *lookup_data.triple_xor_32_45 = [
                    lw[573], lw[574], lw[575], lw[576], lw[577], lw[578], lw[579], lw[580], lw[581],
                ];
                *lookup_data.triple_xor_32_46 = [
                    lw[582], lw[583], lw[584], lw[585], lw[586], lw[587], lw[588], lw[589], lw[590],
                ];
                *lookup_data.triple_xor_32_47 = [
                    lw[591], lw[592], lw[593], lw[594], lw[595], lw[596], lw[597], lw[598], lw[599],
                ];
                *lookup_data.range_check_7_2_5_48 = [lw[600], lw[601], lw[602], lw[603]];
                *lookup_data.memory_address_to_id_49 = [lw[604], lw[605], lw[606]];
                *lookup_data.memory_id_to_big_50 = [
                    lw[607], lw[608], lw[609], lw[610], lw[611], lw[612], lw[613], lw[614],
                    lw[615], lw[616], lw[617], lw[618], lw[619], lw[620], lw[621], lw[622],
                    lw[623], lw[624], lw[625], lw[626], lw[627], lw[628], lw[629], lw[630],
                    lw[631], lw[632], lw[633], lw[634], lw[635], lw[636],
                ];
                *lookup_data.range_check_7_2_5_51 = [lw[637], lw[638], lw[639], lw[640]];
                *lookup_data.memory_address_to_id_52 = [lw[641], lw[642], lw[643]];
                *lookup_data.memory_id_to_big_53 = [
                    lw[644], lw[645], lw[646], lw[647], lw[648], lw[649], lw[650], lw[651],
                    lw[652], lw[653], lw[654], lw[655], lw[656], lw[657], lw[658], lw[659],
                    lw[660], lw[661], lw[662], lw[663], lw[664], lw[665], lw[666], lw[667],
                    lw[668], lw[669], lw[670], lw[671], lw[672], lw[673],
                ];
                *lookup_data.range_check_7_2_5_54 = [lw[674], lw[675], lw[676], lw[677]];
                *lookup_data.memory_address_to_id_55 = [lw[678], lw[679], lw[680]];
                *lookup_data.memory_id_to_big_56 = [
                    lw[681], lw[682], lw[683], lw[684], lw[685], lw[686], lw[687], lw[688],
                    lw[689], lw[690], lw[691], lw[692], lw[693], lw[694], lw[695], lw[696],
                    lw[697], lw[698], lw[699], lw[700], lw[701], lw[702], lw[703], lw[704],
                    lw[705], lw[706], lw[707], lw[708], lw[709], lw[710],
                ];
                *lookup_data.range_check_7_2_5_57 = [lw[711], lw[712], lw[713], lw[714]];
                *lookup_data.memory_address_to_id_58 = [lw[715], lw[716], lw[717]];
                *lookup_data.memory_id_to_big_59 = [
                    lw[718], lw[719], lw[720], lw[721], lw[722], lw[723], lw[724], lw[725],
                    lw[726], lw[727], lw[728], lw[729], lw[730], lw[731], lw[732], lw[733],
                    lw[734], lw[735], lw[736], lw[737], lw[738], lw[739], lw[740], lw[741],
                    lw[742], lw[743], lw[744], lw[745], lw[746], lw[747],
                ];
                *lookup_data.range_check_7_2_5_60 = [lw[748], lw[749], lw[750], lw[751]];
                *lookup_data.memory_address_to_id_61 = [lw[752], lw[753], lw[754]];
                *lookup_data.memory_id_to_big_62 = [
                    lw[755], lw[756], lw[757], lw[758], lw[759], lw[760], lw[761], lw[762],
                    lw[763], lw[764], lw[765], lw[766], lw[767], lw[768], lw[769], lw[770],
                    lw[771], lw[772], lw[773], lw[774], lw[775], lw[776], lw[777], lw[778],
                    lw[779], lw[780], lw[781], lw[782], lw[783], lw[784],
                ];
                *lookup_data.range_check_7_2_5_63 = [lw[785], lw[786], lw[787], lw[788]];
                *lookup_data.memory_address_to_id_64 = [lw[789], lw[790], lw[791]];
                *lookup_data.memory_id_to_big_65 = [
                    lw[792], lw[793], lw[794], lw[795], lw[796], lw[797], lw[798], lw[799],
                    lw[800], lw[801], lw[802], lw[803], lw[804], lw[805], lw[806], lw[807],
                    lw[808], lw[809], lw[810], lw[811], lw[812], lw[813], lw[814], lw[815],
                    lw[816], lw[817], lw[818], lw[819], lw[820], lw[821],
                ];
                *lookup_data.range_check_7_2_5_66 = [lw[822], lw[823], lw[824], lw[825]];
                *lookup_data.memory_address_to_id_67 = [lw[826], lw[827], lw[828]];
                *lookup_data.memory_id_to_big_68 = [
                    lw[829], lw[830], lw[831], lw[832], lw[833], lw[834], lw[835], lw[836],
                    lw[837], lw[838], lw[839], lw[840], lw[841], lw[842], lw[843], lw[844],
                    lw[845], lw[846], lw[847], lw[848], lw[849], lw[850], lw[851], lw[852],
                    lw[853], lw[854], lw[855], lw[856], lw[857], lw[858],
                ];
                *lookup_data.range_check_7_2_5_69 = [lw[859], lw[860], lw[861], lw[862]];
                *lookup_data.memory_address_to_id_70 = [lw[863], lw[864], lw[865]];
                *lookup_data.memory_id_to_big_71 = [
                    lw[866], lw[867], lw[868], lw[869], lw[870], lw[871], lw[872], lw[873],
                    lw[874], lw[875], lw[876], lw[877], lw[878], lw[879], lw[880], lw[881],
                    lw[882], lw[883], lw[884], lw[885], lw[886], lw[887], lw[888], lw[889],
                    lw[890], lw[891], lw[892], lw[893], lw[894], lw[895],
                ];
                *lookup_data.opcodes_72 = [lw[896], lw[897], lw[898], lw[899]];
                *lookup_data.opcodes_73 = [lw[900], lw[901], lw[902], lw[903]];
                *lookup_data.mults_0 = lw[904];
                *lookup_data.mults_1 = lw[905];
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
                *sub_component_inputs.memory_address_to_id[3] =
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) };
                *sub_component_inputs.memory_address_to_id[4] =
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) };
                *sub_component_inputs.memory_address_to_id[5] =
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) };
                *sub_component_inputs.memory_address_to_id[6] =
                    unsafe { PackedM31::from_simd_unchecked(sw[13]) };
                *sub_component_inputs.memory_address_to_id[7] =
                    unsafe { PackedM31::from_simd_unchecked(sw[14]) };
                *sub_component_inputs.memory_address_to_id[8] =
                    unsafe { PackedM31::from_simd_unchecked(sw[15]) };
                *sub_component_inputs.memory_address_to_id[9] =
                    unsafe { PackedM31::from_simd_unchecked(sw[16]) };
                *sub_component_inputs.memory_address_to_id[10] =
                    unsafe { PackedM31::from_simd_unchecked(sw[17]) };
                *sub_component_inputs.memory_address_to_id[11] =
                    unsafe { PackedM31::from_simd_unchecked(sw[18]) };
                *sub_component_inputs.memory_address_to_id[12] =
                    unsafe { PackedM31::from_simd_unchecked(sw[19]) };
                *sub_component_inputs.memory_address_to_id[13] =
                    unsafe { PackedM31::from_simd_unchecked(sw[20]) };
                *sub_component_inputs.memory_address_to_id[14] =
                    unsafe { PackedM31::from_simd_unchecked(sw[21]) };
                *sub_component_inputs.memory_address_to_id[15] =
                    unsafe { PackedM31::from_simd_unchecked(sw[22]) };
                *sub_component_inputs.memory_address_to_id[16] =
                    unsafe { PackedM31::from_simd_unchecked(sw[23]) };
                *sub_component_inputs.memory_address_to_id[17] =
                    unsafe { PackedM31::from_simd_unchecked(sw[24]) };
                *sub_component_inputs.memory_address_to_id[18] =
                    unsafe { PackedM31::from_simd_unchecked(sw[25]) };
                *sub_component_inputs.memory_address_to_id[19] =
                    unsafe { PackedM31::from_simd_unchecked(sw[26]) };
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[27]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[28]) };
                *sub_component_inputs.memory_id_to_big[2] =
                    unsafe { PackedM31::from_simd_unchecked(sw[29]) };
                *sub_component_inputs.memory_id_to_big[3] =
                    unsafe { PackedM31::from_simd_unchecked(sw[30]) };
                *sub_component_inputs.memory_id_to_big[4] =
                    unsafe { PackedM31::from_simd_unchecked(sw[31]) };
                *sub_component_inputs.memory_id_to_big[5] =
                    unsafe { PackedM31::from_simd_unchecked(sw[32]) };
                *sub_component_inputs.memory_id_to_big[6] =
                    unsafe { PackedM31::from_simd_unchecked(sw[33]) };
                *sub_component_inputs.memory_id_to_big[7] =
                    unsafe { PackedM31::from_simd_unchecked(sw[34]) };
                *sub_component_inputs.memory_id_to_big[8] =
                    unsafe { PackedM31::from_simd_unchecked(sw[35]) };
                *sub_component_inputs.memory_id_to_big[9] =
                    unsafe { PackedM31::from_simd_unchecked(sw[36]) };
                *sub_component_inputs.memory_id_to_big[10] =
                    unsafe { PackedM31::from_simd_unchecked(sw[37]) };
                *sub_component_inputs.memory_id_to_big[11] =
                    unsafe { PackedM31::from_simd_unchecked(sw[38]) };
                *sub_component_inputs.memory_id_to_big[12] =
                    unsafe { PackedM31::from_simd_unchecked(sw[39]) };
                *sub_component_inputs.memory_id_to_big[13] =
                    unsafe { PackedM31::from_simd_unchecked(sw[40]) };
                *sub_component_inputs.memory_id_to_big[14] =
                    unsafe { PackedM31::from_simd_unchecked(sw[41]) };
                *sub_component_inputs.memory_id_to_big[15] =
                    unsafe { PackedM31::from_simd_unchecked(sw[42]) };
                *sub_component_inputs.memory_id_to_big[16] =
                    unsafe { PackedM31::from_simd_unchecked(sw[43]) };
                *sub_component_inputs.memory_id_to_big[17] =
                    unsafe { PackedM31::from_simd_unchecked(sw[44]) };
                *sub_component_inputs.memory_id_to_big[18] =
                    unsafe { PackedM31::from_simd_unchecked(sw[45]) };
                *sub_component_inputs.memory_id_to_big[19] =
                    unsafe { PackedM31::from_simd_unchecked(sw[46]) };
                *sub_component_inputs.range_check_7_2_5[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[48]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[49]) },
                ];
                *sub_component_inputs.range_check_7_2_5[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[50]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[51]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[52]) },
                ];
                *sub_component_inputs.range_check_7_2_5[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[53]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[54]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[55]) },
                ];
                *sub_component_inputs.range_check_7_2_5[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[56]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[57]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[58]) },
                ];
                *sub_component_inputs.range_check_7_2_5[4] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[59]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[60]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[61]) },
                ];
                *sub_component_inputs.range_check_7_2_5[5] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[62]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[63]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[64]) },
                ];
                *sub_component_inputs.range_check_7_2_5[6] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[65]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[66]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[67]) },
                ];
                *sub_component_inputs.range_check_7_2_5[7] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[68]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[69]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[70]) },
                ];
                *sub_component_inputs.range_check_7_2_5[8] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[71]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[72]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[73]) },
                ];
                *sub_component_inputs.range_check_7_2_5[9] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[74]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[75]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[76]) },
                ];
                *sub_component_inputs.range_check_7_2_5[10] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[77]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[78]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[79]) },
                ];
                *sub_component_inputs.range_check_7_2_5[11] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[80]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[81]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[82]) },
                ];
                *sub_component_inputs.range_check_7_2_5[12] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[83]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[84]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[85]) },
                ];
                *sub_component_inputs.range_check_7_2_5[13] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[86]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[87]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[88]) },
                ];
                *sub_component_inputs.range_check_7_2_5[14] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[89]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[90]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[91]) },
                ];
                *sub_component_inputs.range_check_7_2_5[15] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[92]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[93]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[94]) },
                ];
                *sub_component_inputs.range_check_7_2_5[16] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[95]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[96]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[97]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[98]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[99]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[100]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[101]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[102]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[103]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[104]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[105]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[106]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[107]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[108]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[109]) },
                ];
                *sub_component_inputs.blake_round[0] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[110]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[111]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[112]),
                            PackedUInt32::from_simd(sw[113]),
                            PackedUInt32::from_simd(sw[114]),
                            PackedUInt32::from_simd(sw[115]),
                            PackedUInt32::from_simd(sw[116]),
                            PackedUInt32::from_simd(sw[117]),
                            PackedUInt32::from_simd(sw[118]),
                            PackedUInt32::from_simd(sw[119]),
                            PackedUInt32::from_simd(sw[120]),
                            PackedUInt32::from_simd(sw[121]),
                            PackedUInt32::from_simd(sw[122]),
                            PackedUInt32::from_simd(sw[123]),
                            PackedUInt32::from_simd(sw[124]),
                            PackedUInt32::from_simd(sw[125]),
                            PackedUInt32::from_simd(sw[126]),
                            PackedUInt32::from_simd(sw[127]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[128]) },
                    ),
                );
                *sub_component_inputs.blake_round[1] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[129]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[130]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[131]),
                            PackedUInt32::from_simd(sw[132]),
                            PackedUInt32::from_simd(sw[133]),
                            PackedUInt32::from_simd(sw[134]),
                            PackedUInt32::from_simd(sw[135]),
                            PackedUInt32::from_simd(sw[136]),
                            PackedUInt32::from_simd(sw[137]),
                            PackedUInt32::from_simd(sw[138]),
                            PackedUInt32::from_simd(sw[139]),
                            PackedUInt32::from_simd(sw[140]),
                            PackedUInt32::from_simd(sw[141]),
                            PackedUInt32::from_simd(sw[142]),
                            PackedUInt32::from_simd(sw[143]),
                            PackedUInt32::from_simd(sw[144]),
                            PackedUInt32::from_simd(sw[145]),
                            PackedUInt32::from_simd(sw[146]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[147]) },
                    ),
                );
                *sub_component_inputs.blake_round[2] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[148]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[149]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[150]),
                            PackedUInt32::from_simd(sw[151]),
                            PackedUInt32::from_simd(sw[152]),
                            PackedUInt32::from_simd(sw[153]),
                            PackedUInt32::from_simd(sw[154]),
                            PackedUInt32::from_simd(sw[155]),
                            PackedUInt32::from_simd(sw[156]),
                            PackedUInt32::from_simd(sw[157]),
                            PackedUInt32::from_simd(sw[158]),
                            PackedUInt32::from_simd(sw[159]),
                            PackedUInt32::from_simd(sw[160]),
                            PackedUInt32::from_simd(sw[161]),
                            PackedUInt32::from_simd(sw[162]),
                            PackedUInt32::from_simd(sw[163]),
                            PackedUInt32::from_simd(sw[164]),
                            PackedUInt32::from_simd(sw[165]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[166]) },
                    ),
                );
                *sub_component_inputs.blake_round[3] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[167]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[168]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[169]),
                            PackedUInt32::from_simd(sw[170]),
                            PackedUInt32::from_simd(sw[171]),
                            PackedUInt32::from_simd(sw[172]),
                            PackedUInt32::from_simd(sw[173]),
                            PackedUInt32::from_simd(sw[174]),
                            PackedUInt32::from_simd(sw[175]),
                            PackedUInt32::from_simd(sw[176]),
                            PackedUInt32::from_simd(sw[177]),
                            PackedUInt32::from_simd(sw[178]),
                            PackedUInt32::from_simd(sw[179]),
                            PackedUInt32::from_simd(sw[180]),
                            PackedUInt32::from_simd(sw[181]),
                            PackedUInt32::from_simd(sw[182]),
                            PackedUInt32::from_simd(sw[183]),
                            PackedUInt32::from_simd(sw[184]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[185]) },
                    ),
                );
                *sub_component_inputs.blake_round[4] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[186]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[187]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[188]),
                            PackedUInt32::from_simd(sw[189]),
                            PackedUInt32::from_simd(sw[190]),
                            PackedUInt32::from_simd(sw[191]),
                            PackedUInt32::from_simd(sw[192]),
                            PackedUInt32::from_simd(sw[193]),
                            PackedUInt32::from_simd(sw[194]),
                            PackedUInt32::from_simd(sw[195]),
                            PackedUInt32::from_simd(sw[196]),
                            PackedUInt32::from_simd(sw[197]),
                            PackedUInt32::from_simd(sw[198]),
                            PackedUInt32::from_simd(sw[199]),
                            PackedUInt32::from_simd(sw[200]),
                            PackedUInt32::from_simd(sw[201]),
                            PackedUInt32::from_simd(sw[202]),
                            PackedUInt32::from_simd(sw[203]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[204]) },
                    ),
                );
                *sub_component_inputs.blake_round[5] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[205]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[206]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[207]),
                            PackedUInt32::from_simd(sw[208]),
                            PackedUInt32::from_simd(sw[209]),
                            PackedUInt32::from_simd(sw[210]),
                            PackedUInt32::from_simd(sw[211]),
                            PackedUInt32::from_simd(sw[212]),
                            PackedUInt32::from_simd(sw[213]),
                            PackedUInt32::from_simd(sw[214]),
                            PackedUInt32::from_simd(sw[215]),
                            PackedUInt32::from_simd(sw[216]),
                            PackedUInt32::from_simd(sw[217]),
                            PackedUInt32::from_simd(sw[218]),
                            PackedUInt32::from_simd(sw[219]),
                            PackedUInt32::from_simd(sw[220]),
                            PackedUInt32::from_simd(sw[221]),
                            PackedUInt32::from_simd(sw[222]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[223]) },
                    ),
                );
                *sub_component_inputs.blake_round[6] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[224]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[225]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[226]),
                            PackedUInt32::from_simd(sw[227]),
                            PackedUInt32::from_simd(sw[228]),
                            PackedUInt32::from_simd(sw[229]),
                            PackedUInt32::from_simd(sw[230]),
                            PackedUInt32::from_simd(sw[231]),
                            PackedUInt32::from_simd(sw[232]),
                            PackedUInt32::from_simd(sw[233]),
                            PackedUInt32::from_simd(sw[234]),
                            PackedUInt32::from_simd(sw[235]),
                            PackedUInt32::from_simd(sw[236]),
                            PackedUInt32::from_simd(sw[237]),
                            PackedUInt32::from_simd(sw[238]),
                            PackedUInt32::from_simd(sw[239]),
                            PackedUInt32::from_simd(sw[240]),
                            PackedUInt32::from_simd(sw[241]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[242]) },
                    ),
                );
                *sub_component_inputs.blake_round[7] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[243]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[244]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[245]),
                            PackedUInt32::from_simd(sw[246]),
                            PackedUInt32::from_simd(sw[247]),
                            PackedUInt32::from_simd(sw[248]),
                            PackedUInt32::from_simd(sw[249]),
                            PackedUInt32::from_simd(sw[250]),
                            PackedUInt32::from_simd(sw[251]),
                            PackedUInt32::from_simd(sw[252]),
                            PackedUInt32::from_simd(sw[253]),
                            PackedUInt32::from_simd(sw[254]),
                            PackedUInt32::from_simd(sw[255]),
                            PackedUInt32::from_simd(sw[256]),
                            PackedUInt32::from_simd(sw[257]),
                            PackedUInt32::from_simd(sw[258]),
                            PackedUInt32::from_simd(sw[259]),
                            PackedUInt32::from_simd(sw[260]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[261]) },
                    ),
                );
                *sub_component_inputs.blake_round[8] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[262]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[263]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[264]),
                            PackedUInt32::from_simd(sw[265]),
                            PackedUInt32::from_simd(sw[266]),
                            PackedUInt32::from_simd(sw[267]),
                            PackedUInt32::from_simd(sw[268]),
                            PackedUInt32::from_simd(sw[269]),
                            PackedUInt32::from_simd(sw[270]),
                            PackedUInt32::from_simd(sw[271]),
                            PackedUInt32::from_simd(sw[272]),
                            PackedUInt32::from_simd(sw[273]),
                            PackedUInt32::from_simd(sw[274]),
                            PackedUInt32::from_simd(sw[275]),
                            PackedUInt32::from_simd(sw[276]),
                            PackedUInt32::from_simd(sw[277]),
                            PackedUInt32::from_simd(sw[278]),
                            PackedUInt32::from_simd(sw[279]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[280]) },
                    ),
                );
                *sub_component_inputs.blake_round[9] = (
                    unsafe { PackedM31::from_simd_unchecked(sw[281]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[282]) },
                    (
                        [
                            PackedUInt32::from_simd(sw[283]),
                            PackedUInt32::from_simd(sw[284]),
                            PackedUInt32::from_simd(sw[285]),
                            PackedUInt32::from_simd(sw[286]),
                            PackedUInt32::from_simd(sw[287]),
                            PackedUInt32::from_simd(sw[288]),
                            PackedUInt32::from_simd(sw[289]),
                            PackedUInt32::from_simd(sw[290]),
                            PackedUInt32::from_simd(sw[291]),
                            PackedUInt32::from_simd(sw[292]),
                            PackedUInt32::from_simd(sw[293]),
                            PackedUInt32::from_simd(sw[294]),
                            PackedUInt32::from_simd(sw[295]),
                            PackedUInt32::from_simd(sw[296]),
                            PackedUInt32::from_simd(sw[297]),
                            PackedUInt32::from_simd(sw[298]),
                        ],
                        unsafe { PackedM31::from_simd_unchecked(sw[299]) },
                    ),
                );
                *sub_component_inputs.triple_xor_32[0] = [
                    PackedUInt32::from_simd(sw[300]),
                    PackedUInt32::from_simd(sw[301]),
                    PackedUInt32::from_simd(sw[302]),
                ];
                *sub_component_inputs.triple_xor_32[1] = [
                    PackedUInt32::from_simd(sw[303]),
                    PackedUInt32::from_simd(sw[304]),
                    PackedUInt32::from_simd(sw[305]),
                ];
                *sub_component_inputs.triple_xor_32[2] = [
                    PackedUInt32::from_simd(sw[306]),
                    PackedUInt32::from_simd(sw[307]),
                    PackedUInt32::from_simd(sw[308]),
                ];
                *sub_component_inputs.triple_xor_32[3] = [
                    PackedUInt32::from_simd(sw[309]),
                    PackedUInt32::from_simd(sw[310]),
                    PackedUInt32::from_simd(sw[311]),
                ];
                *sub_component_inputs.triple_xor_32[4] = [
                    PackedUInt32::from_simd(sw[312]),
                    PackedUInt32::from_simd(sw[313]),
                    PackedUInt32::from_simd(sw[314]),
                ];
                *sub_component_inputs.triple_xor_32[5] = [
                    PackedUInt32::from_simd(sw[315]),
                    PackedUInt32::from_simd(sw[316]),
                    PackedUInt32::from_simd(sw[317]),
                ];
                *sub_component_inputs.triple_xor_32[6] = [
                    PackedUInt32::from_simd(sw[318]),
                    PackedUInt32::from_simd(sw[319]),
                    PackedUInt32::from_simd(sw[320]),
                ];
                *sub_component_inputs.triple_xor_32[7] = [
                    PackedUInt32::from_simd(sw[321]),
                    PackedUInt32::from_simd(sw[322]),
                    PackedUInt32::from_simd(sw[323]),
                ];
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
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
        blake_round_state: &blake_round::ClaimGenerator,
        triple_xor_32_state: &triple_xor_32::ClaimGenerator,
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
            range_check_7_2_5_state,
            verify_bitwise_xor_8_state,
            blake_round_state,
            triple_xor_32_state,
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
        for inputs in sub_component_inputs.range_check_7_2_5 {
            add_inputs(range_check_7_2_5_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.blake_round {
            add_inputs(blake_round_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.triple_xor_32 {
            add_inputs(triple_xor_32_state, &inputs, inputs.len() * N_LANES, 0);
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

/// Record the `blake_compress_opcode` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_blake_compress_opcode() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("blake_compress_opcode", 3, Some(4));
    blake_compress_opcode_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    906;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    memory_address_to_id_5: 3,
    memory_id_to_big_6: 30,
    range_check_7_2_5_7: 4,
    memory_address_to_id_8: 3,
    memory_id_to_big_9: 30,
    range_check_7_2_5_10: 4,
    memory_address_to_id_11: 3,
    memory_id_to_big_12: 30,
    range_check_7_2_5_13: 4,
    memory_address_to_id_14: 3,
    memory_id_to_big_15: 30,
    range_check_7_2_5_16: 4,
    memory_address_to_id_17: 3,
    memory_id_to_big_18: 30,
    range_check_7_2_5_19: 4,
    memory_address_to_id_20: 3,
    memory_id_to_big_21: 30,
    range_check_7_2_5_22: 4,
    memory_address_to_id_23: 3,
    memory_id_to_big_24: 30,
    range_check_7_2_5_25: 4,
    memory_address_to_id_26: 3,
    memory_id_to_big_27: 30,
    range_check_7_2_5_28: 4,
    memory_address_to_id_29: 3,
    memory_id_to_big_30: 30,
    range_check_7_2_5_31: 4,
    memory_address_to_id_32: 3,
    memory_id_to_big_33: 30,
    verify_bitwise_xor_8_34: 4,
    verify_bitwise_xor_8_35: 4,
    verify_bitwise_xor_8_36: 4,
    verify_bitwise_xor_8_37: 4,
    blake_round_38: 36,
    blake_round_39: 36,
    triple_xor_32_40: 9,
    triple_xor_32_41: 9,
    triple_xor_32_42: 9,
    triple_xor_32_43: 9,
    triple_xor_32_44: 9,
    triple_xor_32_45: 9,
    triple_xor_32_46: 9,
    triple_xor_32_47: 9,
    range_check_7_2_5_48: 4,
    memory_address_to_id_49: 3,
    memory_id_to_big_50: 30,
    range_check_7_2_5_51: 4,
    memory_address_to_id_52: 3,
    memory_id_to_big_53: 30,
    range_check_7_2_5_54: 4,
    memory_address_to_id_55: 3,
    memory_id_to_big_56: 30,
    range_check_7_2_5_57: 4,
    memory_address_to_id_58: 3,
    memory_id_to_big_59: 30,
    range_check_7_2_5_60: 4,
    memory_address_to_id_61: 3,
    memory_id_to_big_62: 30,
    range_check_7_2_5_63: 4,
    memory_address_to_id_64: 3,
    memory_id_to_big_65: 30,
    range_check_7_2_5_66: 4,
    memory_address_to_id_67: 3,
    memory_id_to_big_68: 30,
    range_check_7_2_5_69: 4,
    memory_address_to_id_70: 3,
    memory_id_to_big_71: 30,
    opcodes_72: 4,
    opcodes_73: 4,
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
    (
        "memory_address_to_id",
        3,
        "memory_address_to_id_state",
        0,
        10,
        1,
    ),
    (
        "memory_address_to_id",
        4,
        "memory_address_to_id_state",
        0,
        11,
        1,
    ),
    (
        "memory_address_to_id",
        5,
        "memory_address_to_id_state",
        0,
        12,
        1,
    ),
    (
        "memory_address_to_id",
        6,
        "memory_address_to_id_state",
        0,
        13,
        1,
    ),
    (
        "memory_address_to_id",
        7,
        "memory_address_to_id_state",
        0,
        14,
        1,
    ),
    (
        "memory_address_to_id",
        8,
        "memory_address_to_id_state",
        0,
        15,
        1,
    ),
    (
        "memory_address_to_id",
        9,
        "memory_address_to_id_state",
        0,
        16,
        1,
    ),
    (
        "memory_address_to_id",
        10,
        "memory_address_to_id_state",
        0,
        17,
        1,
    ),
    (
        "memory_address_to_id",
        11,
        "memory_address_to_id_state",
        0,
        18,
        1,
    ),
    (
        "memory_address_to_id",
        12,
        "memory_address_to_id_state",
        0,
        19,
        1,
    ),
    (
        "memory_address_to_id",
        13,
        "memory_address_to_id_state",
        0,
        20,
        1,
    ),
    (
        "memory_address_to_id",
        14,
        "memory_address_to_id_state",
        0,
        21,
        1,
    ),
    (
        "memory_address_to_id",
        15,
        "memory_address_to_id_state",
        0,
        22,
        1,
    ),
    (
        "memory_address_to_id",
        16,
        "memory_address_to_id_state",
        0,
        23,
        1,
    ),
    (
        "memory_address_to_id",
        17,
        "memory_address_to_id_state",
        0,
        24,
        1,
    ),
    (
        "memory_address_to_id",
        18,
        "memory_address_to_id_state",
        0,
        25,
        1,
    ),
    (
        "memory_address_to_id",
        19,
        "memory_address_to_id_state",
        0,
        26,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 27, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 28, 1),
    ("memory_id_to_big", 2, "memory_id_to_big_state", 0, 29, 1),
    ("memory_id_to_big", 3, "memory_id_to_big_state", 0, 30, 1),
    ("memory_id_to_big", 4, "memory_id_to_big_state", 0, 31, 1),
    ("memory_id_to_big", 5, "memory_id_to_big_state", 0, 32, 1),
    ("memory_id_to_big", 6, "memory_id_to_big_state", 0, 33, 1),
    ("memory_id_to_big", 7, "memory_id_to_big_state", 0, 34, 1),
    ("memory_id_to_big", 8, "memory_id_to_big_state", 0, 35, 1),
    ("memory_id_to_big", 9, "memory_id_to_big_state", 0, 36, 1),
    ("memory_id_to_big", 10, "memory_id_to_big_state", 0, 37, 1),
    ("memory_id_to_big", 11, "memory_id_to_big_state", 0, 38, 1),
    ("memory_id_to_big", 12, "memory_id_to_big_state", 0, 39, 1),
    ("memory_id_to_big", 13, "memory_id_to_big_state", 0, 40, 1),
    ("memory_id_to_big", 14, "memory_id_to_big_state", 0, 41, 1),
    ("memory_id_to_big", 15, "memory_id_to_big_state", 0, 42, 1),
    ("memory_id_to_big", 16, "memory_id_to_big_state", 0, 43, 1),
    ("memory_id_to_big", 17, "memory_id_to_big_state", 0, 44, 1),
    ("memory_id_to_big", 18, "memory_id_to_big_state", 0, 45, 1),
    ("memory_id_to_big", 19, "memory_id_to_big_state", 0, 46, 1),
    ("range_check_7_2_5", 0, "range_check_7_2_5_state", 0, 47, 3),
    ("range_check_7_2_5", 1, "range_check_7_2_5_state", 0, 50, 3),
    ("range_check_7_2_5", 2, "range_check_7_2_5_state", 0, 53, 3),
    ("range_check_7_2_5", 3, "range_check_7_2_5_state", 0, 56, 3),
    ("range_check_7_2_5", 4, "range_check_7_2_5_state", 0, 59, 3),
    ("range_check_7_2_5", 5, "range_check_7_2_5_state", 0, 62, 3),
    ("range_check_7_2_5", 6, "range_check_7_2_5_state", 0, 65, 3),
    ("range_check_7_2_5", 7, "range_check_7_2_5_state", 0, 68, 3),
    ("range_check_7_2_5", 8, "range_check_7_2_5_state", 0, 71, 3),
    ("range_check_7_2_5", 9, "range_check_7_2_5_state", 0, 74, 3),
    ("range_check_7_2_5", 10, "range_check_7_2_5_state", 0, 77, 3),
    ("range_check_7_2_5", 11, "range_check_7_2_5_state", 0, 80, 3),
    ("range_check_7_2_5", 12, "range_check_7_2_5_state", 0, 83, 3),
    ("range_check_7_2_5", 13, "range_check_7_2_5_state", 0, 86, 3),
    ("range_check_7_2_5", 14, "range_check_7_2_5_state", 0, 89, 3),
    ("range_check_7_2_5", 15, "range_check_7_2_5_state", 0, 92, 3),
    ("range_check_7_2_5", 16, "range_check_7_2_5_state", 0, 95, 3),
    (
        "verify_bitwise_xor_8",
        0,
        "verify_bitwise_xor_8_state",
        0,
        98,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        1,
        "verify_bitwise_xor_8_state",
        0,
        101,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        2,
        "verify_bitwise_xor_8_state",
        0,
        104,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        3,
        "verify_bitwise_xor_8_state",
        0,
        107,
        3,
    ),
    ("blake_round", 0, "blake_round_state", 0, 110, 19),
    ("blake_round", 1, "blake_round_state", 0, 129, 19),
    ("blake_round", 2, "blake_round_state", 0, 148, 19),
    ("blake_round", 3, "blake_round_state", 0, 167, 19),
    ("blake_round", 4, "blake_round_state", 0, 186, 19),
    ("blake_round", 5, "blake_round_state", 0, 205, 19),
    ("blake_round", 6, "blake_round_state", 0, 224, 19),
    ("blake_round", 7, "blake_round_state", 0, 243, 19),
    ("blake_round", 8, "blake_round_state", 0, 262, 19),
    ("blake_round", 9, "blake_round_state", 0, 281, 19),
    ("triple_xor_32", 0, "triple_xor_32_state", 0, 300, 3),
    ("triple_xor_32", 1, "triple_xor_32_state", 0, 303, 3),
    ("triple_xor_32", 2, "triple_xor_32_state", 0, 306, 3),
    ("triple_xor_32", 3, "triple_xor_32_state", 0, 309, 3),
    ("triple_xor_32", 4, "triple_xor_32_state", 0, 312, 3),
    ("triple_xor_32", 5, "triple_xor_32_state", 0, 315, 3),
    ("triple_xor_32", 6, "triple_xor_32_state", 0, 318, 3),
    ("triple_xor_32", 7, "triple_xor_32_state", 0, 321, 3),
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
        "range_check_7_2_5_7",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_8",
        "mults_0",
        false,
        "memory_id_to_big_9",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_10",
        "mults_0",
        false,
        "memory_address_to_id_11",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_12",
        "mults_0",
        false,
        "range_check_7_2_5_13",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_14",
        "mults_0",
        false,
        "memory_id_to_big_15",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_16",
        "mults_0",
        false,
        "memory_address_to_id_17",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_18",
        "mults_0",
        false,
        "range_check_7_2_5_19",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_20",
        "mults_0",
        false,
        "memory_id_to_big_21",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_22",
        "mults_0",
        false,
        "memory_address_to_id_23",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_24",
        "mults_0",
        false,
        "range_check_7_2_5_25",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_26",
        "mults_0",
        false,
        "memory_id_to_big_27",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_28",
        "mults_0",
        false,
        "memory_address_to_id_29",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_30",
        "mults_0",
        false,
        "range_check_7_2_5_31",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_32",
        "mults_0",
        false,
        "memory_id_to_big_33",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_8_34",
        "mults_0",
        false,
        "verify_bitwise_xor_8_35",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_8_36",
        "mults_0",
        false,
        "verify_bitwise_xor_8_37",
        "mults_0",
        false,
    ),
    (
        "blake_round_38",
        "mults_0",
        true,
        "blake_round_39",
        "mults_0",
        false,
    ),
    (
        "triple_xor_32_40",
        "mults_0",
        false,
        "triple_xor_32_41",
        "mults_0",
        false,
    ),
    (
        "triple_xor_32_42",
        "mults_0",
        false,
        "triple_xor_32_43",
        "mults_0",
        false,
    ),
    (
        "triple_xor_32_44",
        "mults_0",
        false,
        "triple_xor_32_45",
        "mults_0",
        false,
    ),
    (
        "triple_xor_32_46",
        "mults_0",
        false,
        "triple_xor_32_47",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_48",
        "mults_0",
        false,
        "memory_address_to_id_49",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_50",
        "mults_0",
        false,
        "range_check_7_2_5_51",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_52",
        "mults_0",
        false,
        "memory_id_to_big_53",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_54",
        "mults_0",
        false,
        "memory_address_to_id_55",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_56",
        "mults_0",
        false,
        "range_check_7_2_5_57",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_58",
        "mults_0",
        false,
        "memory_id_to_big_59",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_60",
        "mults_0",
        false,
        "memory_address_to_id_61",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_62",
        "mults_0",
        false,
        "range_check_7_2_5_63",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_64",
        "mults_0",
        false,
        "memory_id_to_big_65",
        "mults_0",
        false,
    ),
    (
        "range_check_7_2_5_66",
        "mults_0",
        false,
        "memory_address_to_id_67",
        "mults_0",
        false,
    ),
    (
        "memory_id_to_big_68",
        "mults_0",
        false,
        "range_check_7_2_5_69",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_70",
        "mults_0",
        false,
        "memory_id_to_big_71",
        "mults_0",
        false,
    ),
    (
        "opcodes_72",
        "mults_1",
        false,
        "opcodes_73",
        "mults_1",
        true,
    ),
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
        ld.range_check_7_2_5_7.iter().flatten().copied().collect(),
        ld.memory_address_to_id_8
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_9.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_10.iter().flatten().copied().collect(),
        ld.memory_address_to_id_11
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_12.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_13.iter().flatten().copied().collect(),
        ld.memory_address_to_id_14
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_15.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_16.iter().flatten().copied().collect(),
        ld.memory_address_to_id_17
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_18.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_19.iter().flatten().copied().collect(),
        ld.memory_address_to_id_20
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_21.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_22.iter().flatten().copied().collect(),
        ld.memory_address_to_id_23
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_24.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_25.iter().flatten().copied().collect(),
        ld.memory_address_to_id_26
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_27.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_28.iter().flatten().copied().collect(),
        ld.memory_address_to_id_29
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_30.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_31.iter().flatten().copied().collect(),
        ld.memory_address_to_id_32
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_33.iter().flatten().copied().collect(),
        ld.verify_bitwise_xor_8_34
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_35
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_36
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_37
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.blake_round_38.iter().flatten().copied().collect(),
        ld.blake_round_39.iter().flatten().copied().collect(),
        ld.triple_xor_32_40.iter().flatten().copied().collect(),
        ld.triple_xor_32_41.iter().flatten().copied().collect(),
        ld.triple_xor_32_42.iter().flatten().copied().collect(),
        ld.triple_xor_32_43.iter().flatten().copied().collect(),
        ld.triple_xor_32_44.iter().flatten().copied().collect(),
        ld.triple_xor_32_45.iter().flatten().copied().collect(),
        ld.triple_xor_32_46.iter().flatten().copied().collect(),
        ld.triple_xor_32_47.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_48.iter().flatten().copied().collect(),
        ld.memory_address_to_id_49
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_50.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_51.iter().flatten().copied().collect(),
        ld.memory_address_to_id_52
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_53.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_54.iter().flatten().copied().collect(),
        ld.memory_address_to_id_55
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_56.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_57.iter().flatten().copied().collect(),
        ld.memory_address_to_id_58
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_59.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_60.iter().flatten().copied().collect(),
        ld.memory_address_to_id_61
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_62.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_63.iter().flatten().copied().collect(),
        ld.memory_address_to_id_64
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_65.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_66.iter().flatten().copied().collect(),
        ld.memory_address_to_id_67
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_68.iter().flatten().copied().collect(),
        ld.range_check_7_2_5_69.iter().flatten().copied().collect(),
        ld.memory_address_to_id_70
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_71.iter().flatten().copied().collect(),
        ld.opcodes_72.iter().flatten().copied().collect(),
        ld.opcodes_73.iter().flatten().copied().collect(),
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
        sci.memory_address_to_id[3]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[4]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[5]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[6]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[7]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[8]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[9]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[10]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[11]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[12]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[13]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[14]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[15]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[16]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[17]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[18]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[19]
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
        sci.memory_id_to_big[3]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[4]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[5]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[6]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[7]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[8]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[9]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[10]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[11]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[12]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[13]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[14]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[15]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[16]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[17]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[18]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[19]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[8]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[9]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[10]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[11]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[12]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[13]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[14]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[15]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_7_2_5[16]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.blake_round[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[6]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[7]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[8]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.blake_round[9]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0.into_simd(),
                    t.1.into_simd(),
                    t.2 .0[0].simd,
                    t.2 .0[1].simd,
                    t.2 .0[2].simd,
                    t.2 .0[3].simd,
                    t.2 .0[4].simd,
                    t.2 .0[5].simd,
                    t.2 .0[6].simd,
                    t.2 .0[7].simd,
                    t.2 .0[8].simd,
                    t.2 .0[9].simd,
                    t.2 .0[10].simd,
                    t.2 .0[11].simd,
                    t.2 .0[12].simd,
                    t.2 .0[13].simd,
                    t.2 .0[14].simd,
                    t.2 .0[15].simd,
                    t.2 .1.into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.triple_xor_32[0]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[1]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[2]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[3]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[4]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[5]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[6]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
            .collect::<Vec<_>>(),
        sci.triple_xor_32[7]
            .iter()
            .flat_map(|t| vec![t[0].simd, t[1].simd, t[2].simd])
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
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
    blake_round_state: &blake_round::ClaimGenerator,
    triple_xor_32_state: &triple_xor_32::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
        range_check_7_2_5_state,
        verify_bitwise_xor_8_state,
        blake_round_state,
        triple_xor_32_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_instruction_state,
        range_check_7_2_5_state,
        verify_bitwise_xor_8_state,
        blake_round_state,
        triple_xor_32_state,
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
    range_check_7_2_5_7: Vec<[PackedM31; 4]>,
    memory_address_to_id_8: Vec<[PackedM31; 3]>,
    memory_id_to_big_9: Vec<[PackedM31; 30]>,
    range_check_7_2_5_10: Vec<[PackedM31; 4]>,
    memory_address_to_id_11: Vec<[PackedM31; 3]>,
    memory_id_to_big_12: Vec<[PackedM31; 30]>,
    range_check_7_2_5_13: Vec<[PackedM31; 4]>,
    memory_address_to_id_14: Vec<[PackedM31; 3]>,
    memory_id_to_big_15: Vec<[PackedM31; 30]>,
    range_check_7_2_5_16: Vec<[PackedM31; 4]>,
    memory_address_to_id_17: Vec<[PackedM31; 3]>,
    memory_id_to_big_18: Vec<[PackedM31; 30]>,
    range_check_7_2_5_19: Vec<[PackedM31; 4]>,
    memory_address_to_id_20: Vec<[PackedM31; 3]>,
    memory_id_to_big_21: Vec<[PackedM31; 30]>,
    range_check_7_2_5_22: Vec<[PackedM31; 4]>,
    memory_address_to_id_23: Vec<[PackedM31; 3]>,
    memory_id_to_big_24: Vec<[PackedM31; 30]>,
    range_check_7_2_5_25: Vec<[PackedM31; 4]>,
    memory_address_to_id_26: Vec<[PackedM31; 3]>,
    memory_id_to_big_27: Vec<[PackedM31; 30]>,
    range_check_7_2_5_28: Vec<[PackedM31; 4]>,
    memory_address_to_id_29: Vec<[PackedM31; 3]>,
    memory_id_to_big_30: Vec<[PackedM31; 30]>,
    range_check_7_2_5_31: Vec<[PackedM31; 4]>,
    memory_address_to_id_32: Vec<[PackedM31; 3]>,
    memory_id_to_big_33: Vec<[PackedM31; 30]>,
    verify_bitwise_xor_8_34: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_35: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_36: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_37: Vec<[PackedM31; 4]>,
    blake_round_38: Vec<[PackedM31; 36]>,
    blake_round_39: Vec<[PackedM31; 36]>,
    triple_xor_32_40: Vec<[PackedM31; 9]>,
    triple_xor_32_41: Vec<[PackedM31; 9]>,
    triple_xor_32_42: Vec<[PackedM31; 9]>,
    triple_xor_32_43: Vec<[PackedM31; 9]>,
    triple_xor_32_44: Vec<[PackedM31; 9]>,
    triple_xor_32_45: Vec<[PackedM31; 9]>,
    triple_xor_32_46: Vec<[PackedM31; 9]>,
    triple_xor_32_47: Vec<[PackedM31; 9]>,
    range_check_7_2_5_48: Vec<[PackedM31; 4]>,
    memory_address_to_id_49: Vec<[PackedM31; 3]>,
    memory_id_to_big_50: Vec<[PackedM31; 30]>,
    range_check_7_2_5_51: Vec<[PackedM31; 4]>,
    memory_address_to_id_52: Vec<[PackedM31; 3]>,
    memory_id_to_big_53: Vec<[PackedM31; 30]>,
    range_check_7_2_5_54: Vec<[PackedM31; 4]>,
    memory_address_to_id_55: Vec<[PackedM31; 3]>,
    memory_id_to_big_56: Vec<[PackedM31; 30]>,
    range_check_7_2_5_57: Vec<[PackedM31; 4]>,
    memory_address_to_id_58: Vec<[PackedM31; 3]>,
    memory_id_to_big_59: Vec<[PackedM31; 30]>,
    range_check_7_2_5_60: Vec<[PackedM31; 4]>,
    memory_address_to_id_61: Vec<[PackedM31; 3]>,
    memory_id_to_big_62: Vec<[PackedM31; 30]>,
    range_check_7_2_5_63: Vec<[PackedM31; 4]>,
    memory_address_to_id_64: Vec<[PackedM31; 3]>,
    memory_id_to_big_65: Vec<[PackedM31; 30]>,
    range_check_7_2_5_66: Vec<[PackedM31; 4]>,
    memory_address_to_id_67: Vec<[PackedM31; 3]>,
    memory_id_to_big_68: Vec<[PackedM31; 30]>,
    range_check_7_2_5_69: Vec<[PackedM31; 4]>,
    memory_address_to_id_70: Vec<[PackedM31; 3]>,
    memory_id_to_big_71: Vec<[PackedM31; 30]>,
    opcodes_72: Vec<[PackedM31; 4]>,
    opcodes_73: Vec<[PackedM31; 4]>,
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
    range_check_7_2_5_7: 4,
    memory_address_to_id_8: 3,
    memory_id_to_big_9: 30,
    range_check_7_2_5_10: 4,
    memory_address_to_id_11: 3,
    memory_id_to_big_12: 30,
    range_check_7_2_5_13: 4,
    memory_address_to_id_14: 3,
    memory_id_to_big_15: 30,
    range_check_7_2_5_16: 4,
    memory_address_to_id_17: 3,
    memory_id_to_big_18: 30,
    range_check_7_2_5_19: 4,
    memory_address_to_id_20: 3,
    memory_id_to_big_21: 30,
    range_check_7_2_5_22: 4,
    memory_address_to_id_23: 3,
    memory_id_to_big_24: 30,
    range_check_7_2_5_25: 4,
    memory_address_to_id_26: 3,
    memory_id_to_big_27: 30,
    range_check_7_2_5_28: 4,
    memory_address_to_id_29: 3,
    memory_id_to_big_30: 30,
    range_check_7_2_5_31: 4,
    memory_address_to_id_32: 3,
    memory_id_to_big_33: 30,
    verify_bitwise_xor_8_34: 4,
    verify_bitwise_xor_8_35: 4,
    verify_bitwise_xor_8_36: 4,
    verify_bitwise_xor_8_37: 4,
    blake_round_38: 36,
    blake_round_39: 36,
    triple_xor_32_40: 9,
    triple_xor_32_41: 9,
    triple_xor_32_42: 9,
    triple_xor_32_43: 9,
    triple_xor_32_44: 9,
    triple_xor_32_45: 9,
    triple_xor_32_46: 9,
    triple_xor_32_47: 9,
    range_check_7_2_5_48: 4,
    memory_address_to_id_49: 3,
    memory_id_to_big_50: 30,
    range_check_7_2_5_51: 4,
    memory_address_to_id_52: 3,
    memory_id_to_big_53: 30,
    range_check_7_2_5_54: 4,
    memory_address_to_id_55: 3,
    memory_id_to_big_56: 30,
    range_check_7_2_5_57: 4,
    memory_address_to_id_58: 3,
    memory_id_to_big_59: 30,
    range_check_7_2_5_60: 4,
    memory_address_to_id_61: 3,
    memory_id_to_big_62: 30,
    range_check_7_2_5_63: 4,
    memory_address_to_id_64: 3,
    memory_id_to_big_65: 30,
    range_check_7_2_5_66: 4,
    memory_address_to_id_67: 3,
    memory_id_to_big_68: 30,
    range_check_7_2_5_69: 4,
    memory_address_to_id_70: 3,
    memory_id_to_big_71: 30,
    opcodes_72: 4,
    opcodes_73: 4,
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
            &self.lookup_data.range_check_7_2_5_7,
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
            &self.lookup_data.memory_address_to_id_8,
            &self.lookup_data.memory_id_to_big_9,
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
            &self.lookup_data.range_check_7_2_5_10,
            &self.lookup_data.memory_address_to_id_11,
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
            &self.lookup_data.memory_id_to_big_12,
            &self.lookup_data.range_check_7_2_5_13,
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
            &self.lookup_data.memory_address_to_id_14,
            &self.lookup_data.memory_id_to_big_15,
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
            &self.lookup_data.range_check_7_2_5_16,
            &self.lookup_data.memory_address_to_id_17,
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
            &self.lookup_data.memory_id_to_big_18,
            &self.lookup_data.range_check_7_2_5_19,
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
            &self.lookup_data.memory_address_to_id_20,
            &self.lookup_data.memory_id_to_big_21,
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
            &self.lookup_data.range_check_7_2_5_22,
            &self.lookup_data.memory_address_to_id_23,
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
            &self.lookup_data.memory_id_to_big_24,
            &self.lookup_data.range_check_7_2_5_25,
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
            &self.lookup_data.memory_address_to_id_26,
            &self.lookup_data.memory_id_to_big_27,
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
            &self.lookup_data.range_check_7_2_5_28,
            &self.lookup_data.memory_address_to_id_29,
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
            &self.lookup_data.memory_id_to_big_30,
            &self.lookup_data.range_check_7_2_5_31,
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
            &self.lookup_data.memory_address_to_id_32,
            &self.lookup_data.memory_id_to_big_33,
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
            &self.lookup_data.verify_bitwise_xor_8_34,
            &self.lookup_data.verify_bitwise_xor_8_35,
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
            &self.lookup_data.verify_bitwise_xor_8_36,
            &self.lookup_data.verify_bitwise_xor_8_37,
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
            &self.lookup_data.blake_round_38,
            &self.lookup_data.blake_round_39,
            &self.lookup_data.mults_0,
            &self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom0 * *mult1 - denom1 * *mult0, denom0 * denom1);
            });
        col_gen.finalize_col();

        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.triple_xor_32_40,
            &self.lookup_data.triple_xor_32_41,
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
            &self.lookup_data.triple_xor_32_42,
            &self.lookup_data.triple_xor_32_43,
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
            &self.lookup_data.triple_xor_32_44,
            &self.lookup_data.triple_xor_32_45,
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
            &self.lookup_data.triple_xor_32_46,
            &self.lookup_data.triple_xor_32_47,
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
            &self.lookup_data.range_check_7_2_5_48,
            &self.lookup_data.memory_address_to_id_49,
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
            &self.lookup_data.memory_id_to_big_50,
            &self.lookup_data.range_check_7_2_5_51,
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
            &self.lookup_data.memory_address_to_id_52,
            &self.lookup_data.memory_id_to_big_53,
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
            &self.lookup_data.range_check_7_2_5_54,
            &self.lookup_data.memory_address_to_id_55,
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
            &self.lookup_data.memory_id_to_big_56,
            &self.lookup_data.range_check_7_2_5_57,
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
            &self.lookup_data.memory_address_to_id_58,
            &self.lookup_data.memory_id_to_big_59,
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
            &self.lookup_data.range_check_7_2_5_60,
            &self.lookup_data.memory_address_to_id_61,
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
            &self.lookup_data.memory_id_to_big_62,
            &self.lookup_data.range_check_7_2_5_63,
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
            &self.lookup_data.memory_address_to_id_64,
            &self.lookup_data.memory_id_to_big_65,
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
            &self.lookup_data.range_check_7_2_5_66,
            &self.lookup_data.memory_address_to_id_67,
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
            &self.lookup_data.memory_id_to_big_68,
            &self.lookup_data.range_check_7_2_5_69,
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
            &self.lookup_data.memory_address_to_id_70,
            &self.lookup_data.memory_id_to_big_71,
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
            &self.lookup_data.opcodes_72,
            &self.lookup_data.opcodes_73,
            &self.lookup_data.mults_1,
            &self.lookup_data.mults_1,
        )
            .into_par_iter()
            .for_each(|(writer, values0, values1, mult0, mult1)| {
                let denom0: PackedQM31 = common_lookup_elements.combine(values0);
                let denom1: PackedQM31 = common_lookup_elements.combine(values1);
                writer.write_frac(denom1 * *mult0 - denom0 * *mult1, denom0 * denom1);
            });
        col_gen.finalize_col();

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
