// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::bitwise_builtin::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    memory_address_to_id, memory_id_to_big, verify_bitwise_xor_8, verify_bitwise_xor_9,
};
use crate::witness::prelude::*;

#[derive(Default)]
pub struct ClaimGenerator {
    pub log_size: u32,
    pub bitwise_builtin_segment_start: u32,
}

impl ClaimGenerator {
    pub fn new(log_size: u32, bitwise_builtin_segment_start: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            log_size,
            bitwise_builtin_segment_start,
        }
    }

    pub fn write_trace(
        self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        verify_bitwise_xor_9_state: &verify_bitwise_xor_9::ClaimGenerator,
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            log_size,
            self.bitwise_builtin_segment_start,
            memory_address_to_id_state,
            memory_id_to_big_state,
            verify_bitwise_xor_9_state,
            verify_bitwise_xor_8_state,
        );
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
        for inputs in sub_component_inputs.verify_bitwise_xor_9 {
            add_inputs(
                verify_bitwise_xor_9_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 5],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 5],
    verify_bitwise_xor_9: [Vec<verify_bitwise_xor_9::PackedInputType>; 27],
    verify_bitwise_xor_8: [Vec<verify_bitwise_xor_8::PackedInputType>; 1],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    log_size: u32,
    bitwise_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_bitwise_xor_9_state: &verify_bitwise_xor_9::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = log_size - LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };

    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1073741824 = PackedM31::broadcast(M31::from(1073741824));
    let M31_112558620 = PackedM31::broadcast(M31::from(112558620));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_5 = PackedM31::broadcast(M31::from(5));
    let M31_95781001 = PackedM31::broadcast(M31::from(95781001));
    let seq = Seq::new(log_size);

    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(|(row_index, (row, lookup_data, sub_component_inputs))| {
            let seq = seq.packed_at(row_index);

            // Read Positive Num Bits 252.

            // Read Id.

            let memory_address_to_id_value_tmp_b8fb8_0 = memory_address_to_id_state.deduce_output(
                ((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5))),
            );
            let op0_id_col0 = memory_address_to_id_value_tmp_b8fb8_0;
            *row[0] = op0_id_col0;
            *sub_component_inputs.memory_address_to_id[0] =
                ((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)));
            *lookup_data.memory_address_to_id_0 = [
                M31_1444891767,
                ((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5))),
                op0_id_col0,
            ];

            // Read Positive Known Id Num Bits 252.

            let memory_id_to_big_value_tmp_b8fb8_2 =
                memory_id_to_big_state.deduce_output(op0_id_col0);
            let op0_limb_0_col1 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(0);
            *row[1] = op0_limb_0_col1;
            let op0_limb_1_col2 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(1);
            *row[2] = op0_limb_1_col2;
            let op0_limb_2_col3 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(2);
            *row[3] = op0_limb_2_col3;
            let op0_limb_3_col4 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(3);
            *row[4] = op0_limb_3_col4;
            let op0_limb_4_col5 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(4);
            *row[5] = op0_limb_4_col5;
            let op0_limb_5_col6 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(5);
            *row[6] = op0_limb_5_col6;
            let op0_limb_6_col7 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(6);
            *row[7] = op0_limb_6_col7;
            let op0_limb_7_col8 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(7);
            *row[8] = op0_limb_7_col8;
            let op0_limb_8_col9 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(8);
            *row[9] = op0_limb_8_col9;
            let op0_limb_9_col10 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(9);
            *row[10] = op0_limb_9_col10;
            let op0_limb_10_col11 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(10);
            *row[11] = op0_limb_10_col11;
            let op0_limb_11_col12 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(11);
            *row[12] = op0_limb_11_col12;
            let op0_limb_12_col13 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(12);
            *row[13] = op0_limb_12_col13;
            let op0_limb_13_col14 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(13);
            *row[14] = op0_limb_13_col14;
            let op0_limb_14_col15 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(14);
            *row[15] = op0_limb_14_col15;
            let op0_limb_15_col16 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(15);
            *row[16] = op0_limb_15_col16;
            let op0_limb_16_col17 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(16);
            *row[17] = op0_limb_16_col17;
            let op0_limb_17_col18 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(17);
            *row[18] = op0_limb_17_col18;
            let op0_limb_18_col19 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(18);
            *row[19] = op0_limb_18_col19;
            let op0_limb_19_col20 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(19);
            *row[20] = op0_limb_19_col20;
            let op0_limb_20_col21 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(20);
            *row[21] = op0_limb_20_col21;
            let op0_limb_21_col22 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(21);
            *row[22] = op0_limb_21_col22;
            let op0_limb_22_col23 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(22);
            *row[23] = op0_limb_22_col23;
            let op0_limb_23_col24 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(23);
            *row[24] = op0_limb_23_col24;
            let op0_limb_24_col25 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(24);
            *row[25] = op0_limb_24_col25;
            let op0_limb_25_col26 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(25);
            *row[26] = op0_limb_25_col26;
            let op0_limb_26_col27 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(26);
            *row[27] = op0_limb_26_col27;
            let op0_limb_27_col28 = memory_id_to_big_value_tmp_b8fb8_2.get_m31(27);
            *row[28] = op0_limb_27_col28;
            *sub_component_inputs.memory_id_to_big[0] = op0_id_col0;
            *lookup_data.memory_id_to_big_1 = [
                M31_1662111297,
                op0_id_col0,
                op0_limb_0_col1,
                op0_limb_1_col2,
                op0_limb_2_col3,
                op0_limb_3_col4,
                op0_limb_4_col5,
                op0_limb_5_col6,
                op0_limb_6_col7,
                op0_limb_7_col8,
                op0_limb_8_col9,
                op0_limb_9_col10,
                op0_limb_10_col11,
                op0_limb_11_col12,
                op0_limb_12_col13,
                op0_limb_13_col14,
                op0_limb_14_col15,
                op0_limb_15_col16,
                op0_limb_16_col17,
                op0_limb_17_col18,
                op0_limb_18_col19,
                op0_limb_19_col20,
                op0_limb_20_col21,
                op0_limb_21_col22,
                op0_limb_22_col23,
                op0_limb_23_col24,
                op0_limb_24_col25,
                op0_limb_25_col26,
                op0_limb_26_col27,
                op0_limb_27_col28,
            ];
            let read_positive_known_id_num_bits_252_output_tmp_b8fb8_3 =
                PackedFelt252::from_limbs([
                    op0_limb_0_col1,
                    op0_limb_1_col2,
                    op0_limb_2_col3,
                    op0_limb_3_col4,
                    op0_limb_4_col5,
                    op0_limb_5_col6,
                    op0_limb_6_col7,
                    op0_limb_7_col8,
                    op0_limb_8_col9,
                    op0_limb_9_col10,
                    op0_limb_10_col11,
                    op0_limb_11_col12,
                    op0_limb_12_col13,
                    op0_limb_13_col14,
                    op0_limb_14_col15,
                    op0_limb_15_col16,
                    op0_limb_16_col17,
                    op0_limb_17_col18,
                    op0_limb_18_col19,
                    op0_limb_19_col20,
                    op0_limb_20_col21,
                    op0_limb_21_col22,
                    op0_limb_22_col23,
                    op0_limb_23_col24,
                    op0_limb_24_col25,
                    op0_limb_25_col26,
                    op0_limb_26_col27,
                    op0_limb_27_col28,
                ]);

            let read_positive_num_bits_252_output_tmp_b8fb8_4 = (
                read_positive_known_id_num_bits_252_output_tmp_b8fb8_3,
                op0_id_col0,
            );

            // Read Positive Num Bits 252.

            // Read Id.

            let memory_address_to_id_value_tmp_b8fb8_5 = memory_address_to_id_state.deduce_output(
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_1)),
            );
            let op1_id_col29 = memory_address_to_id_value_tmp_b8fb8_5;
            *row[29] = op1_id_col29;
            *sub_component_inputs.memory_address_to_id[1] =
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_1));
            *lookup_data.memory_address_to_id_2 = [
                M31_1444891767,
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_1)),
                op1_id_col29,
            ];

            // Read Positive Known Id Num Bits 252.

            let memory_id_to_big_value_tmp_b8fb8_7 =
                memory_id_to_big_state.deduce_output(op1_id_col29);
            let op1_limb_0_col30 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(0);
            *row[30] = op1_limb_0_col30;
            let op1_limb_1_col31 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(1);
            *row[31] = op1_limb_1_col31;
            let op1_limb_2_col32 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(2);
            *row[32] = op1_limb_2_col32;
            let op1_limb_3_col33 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(3);
            *row[33] = op1_limb_3_col33;
            let op1_limb_4_col34 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(4);
            *row[34] = op1_limb_4_col34;
            let op1_limb_5_col35 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(5);
            *row[35] = op1_limb_5_col35;
            let op1_limb_6_col36 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(6);
            *row[36] = op1_limb_6_col36;
            let op1_limb_7_col37 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(7);
            *row[37] = op1_limb_7_col37;
            let op1_limb_8_col38 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(8);
            *row[38] = op1_limb_8_col38;
            let op1_limb_9_col39 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(9);
            *row[39] = op1_limb_9_col39;
            let op1_limb_10_col40 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(10);
            *row[40] = op1_limb_10_col40;
            let op1_limb_11_col41 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(11);
            *row[41] = op1_limb_11_col41;
            let op1_limb_12_col42 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(12);
            *row[42] = op1_limb_12_col42;
            let op1_limb_13_col43 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(13);
            *row[43] = op1_limb_13_col43;
            let op1_limb_14_col44 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(14);
            *row[44] = op1_limb_14_col44;
            let op1_limb_15_col45 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(15);
            *row[45] = op1_limb_15_col45;
            let op1_limb_16_col46 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(16);
            *row[46] = op1_limb_16_col46;
            let op1_limb_17_col47 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(17);
            *row[47] = op1_limb_17_col47;
            let op1_limb_18_col48 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(18);
            *row[48] = op1_limb_18_col48;
            let op1_limb_19_col49 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(19);
            *row[49] = op1_limb_19_col49;
            let op1_limb_20_col50 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(20);
            *row[50] = op1_limb_20_col50;
            let op1_limb_21_col51 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(21);
            *row[51] = op1_limb_21_col51;
            let op1_limb_22_col52 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(22);
            *row[52] = op1_limb_22_col52;
            let op1_limb_23_col53 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(23);
            *row[53] = op1_limb_23_col53;
            let op1_limb_24_col54 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(24);
            *row[54] = op1_limb_24_col54;
            let op1_limb_25_col55 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(25);
            *row[55] = op1_limb_25_col55;
            let op1_limb_26_col56 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(26);
            *row[56] = op1_limb_26_col56;
            let op1_limb_27_col57 = memory_id_to_big_value_tmp_b8fb8_7.get_m31(27);
            *row[57] = op1_limb_27_col57;
            *sub_component_inputs.memory_id_to_big[1] = op1_id_col29;
            *lookup_data.memory_id_to_big_3 = [
                M31_1662111297,
                op1_id_col29,
                op1_limb_0_col30,
                op1_limb_1_col31,
                op1_limb_2_col32,
                op1_limb_3_col33,
                op1_limb_4_col34,
                op1_limb_5_col35,
                op1_limb_6_col36,
                op1_limb_7_col37,
                op1_limb_8_col38,
                op1_limb_9_col39,
                op1_limb_10_col40,
                op1_limb_11_col41,
                op1_limb_12_col42,
                op1_limb_13_col43,
                op1_limb_14_col44,
                op1_limb_15_col45,
                op1_limb_16_col46,
                op1_limb_17_col47,
                op1_limb_18_col48,
                op1_limb_19_col49,
                op1_limb_20_col50,
                op1_limb_21_col51,
                op1_limb_22_col52,
                op1_limb_23_col53,
                op1_limb_24_col54,
                op1_limb_25_col55,
                op1_limb_26_col56,
                op1_limb_27_col57,
            ];
            let read_positive_known_id_num_bits_252_output_tmp_b8fb8_8 =
                PackedFelt252::from_limbs([
                    op1_limb_0_col30,
                    op1_limb_1_col31,
                    op1_limb_2_col32,
                    op1_limb_3_col33,
                    op1_limb_4_col34,
                    op1_limb_5_col35,
                    op1_limb_6_col36,
                    op1_limb_7_col37,
                    op1_limb_8_col38,
                    op1_limb_9_col39,
                    op1_limb_10_col40,
                    op1_limb_11_col41,
                    op1_limb_12_col42,
                    op1_limb_13_col43,
                    op1_limb_14_col44,
                    op1_limb_15_col45,
                    op1_limb_16_col46,
                    op1_limb_17_col47,
                    op1_limb_18_col48,
                    op1_limb_19_col49,
                    op1_limb_20_col50,
                    op1_limb_21_col51,
                    op1_limb_22_col52,
                    op1_limb_23_col53,
                    op1_limb_24_col54,
                    op1_limb_25_col55,
                    op1_limb_26_col56,
                    op1_limb_27_col57,
                ]);

            let read_positive_num_bits_252_output_tmp_b8fb8_9 = (
                read_positive_known_id_num_bits_252_output_tmp_b8fb8_8,
                op1_id_col29,
            );

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_10 = ((PackedUInt16::from_m31(op0_limb_0_col1))
                ^ (PackedUInt16::from_m31(op1_limb_0_col30)));
            let xor_col58 = xor_tmp_b8fb8_10.as_m31();
            *row[58] = xor_col58;
            *sub_component_inputs.verify_bitwise_xor_9[0] =
                [op0_limb_0_col1, op1_limb_0_col30, xor_col58];
            *lookup_data.verify_bitwise_xor_9_4 =
                [M31_95781001, op0_limb_0_col1, op1_limb_0_col30, xor_col58];

            let and_tmp_b8fb8_12 =
                ((M31_1073741824) * (((op0_limb_0_col1) + (op1_limb_0_col30)) - (xor_col58)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_13 = ((PackedUInt16::from_m31(op0_limb_1_col2))
                ^ (PackedUInt16::from_m31(op1_limb_1_col31)));
            let xor_col59 = xor_tmp_b8fb8_13.as_m31();
            *row[59] = xor_col59;
            *sub_component_inputs.verify_bitwise_xor_9[1] =
                [op0_limb_1_col2, op1_limb_1_col31, xor_col59];
            *lookup_data.verify_bitwise_xor_9_5 =
                [M31_95781001, op0_limb_1_col2, op1_limb_1_col31, xor_col59];

            let and_tmp_b8fb8_15 =
                ((M31_1073741824) * (((op0_limb_1_col2) + (op1_limb_1_col31)) - (xor_col59)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_16 = ((PackedUInt16::from_m31(op0_limb_2_col3))
                ^ (PackedUInt16::from_m31(op1_limb_2_col32)));
            let xor_col60 = xor_tmp_b8fb8_16.as_m31();
            *row[60] = xor_col60;
            *sub_component_inputs.verify_bitwise_xor_9[2] =
                [op0_limb_2_col3, op1_limb_2_col32, xor_col60];
            *lookup_data.verify_bitwise_xor_9_6 =
                [M31_95781001, op0_limb_2_col3, op1_limb_2_col32, xor_col60];

            let and_tmp_b8fb8_18 =
                ((M31_1073741824) * (((op0_limb_2_col3) + (op1_limb_2_col32)) - (xor_col60)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_19 = ((PackedUInt16::from_m31(op0_limb_3_col4))
                ^ (PackedUInt16::from_m31(op1_limb_3_col33)));
            let xor_col61 = xor_tmp_b8fb8_19.as_m31();
            *row[61] = xor_col61;
            *sub_component_inputs.verify_bitwise_xor_9[3] =
                [op0_limb_3_col4, op1_limb_3_col33, xor_col61];
            *lookup_data.verify_bitwise_xor_9_7 =
                [M31_95781001, op0_limb_3_col4, op1_limb_3_col33, xor_col61];

            let and_tmp_b8fb8_21 =
                ((M31_1073741824) * (((op0_limb_3_col4) + (op1_limb_3_col33)) - (xor_col61)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_22 = ((PackedUInt16::from_m31(op0_limb_4_col5))
                ^ (PackedUInt16::from_m31(op1_limb_4_col34)));
            let xor_col62 = xor_tmp_b8fb8_22.as_m31();
            *row[62] = xor_col62;
            *sub_component_inputs.verify_bitwise_xor_9[4] =
                [op0_limb_4_col5, op1_limb_4_col34, xor_col62];
            *lookup_data.verify_bitwise_xor_9_8 =
                [M31_95781001, op0_limb_4_col5, op1_limb_4_col34, xor_col62];

            let and_tmp_b8fb8_24 =
                ((M31_1073741824) * (((op0_limb_4_col5) + (op1_limb_4_col34)) - (xor_col62)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_25 = ((PackedUInt16::from_m31(op0_limb_5_col6))
                ^ (PackedUInt16::from_m31(op1_limb_5_col35)));
            let xor_col63 = xor_tmp_b8fb8_25.as_m31();
            *row[63] = xor_col63;
            *sub_component_inputs.verify_bitwise_xor_9[5] =
                [op0_limb_5_col6, op1_limb_5_col35, xor_col63];
            *lookup_data.verify_bitwise_xor_9_9 =
                [M31_95781001, op0_limb_5_col6, op1_limb_5_col35, xor_col63];

            let and_tmp_b8fb8_27 =
                ((M31_1073741824) * (((op0_limb_5_col6) + (op1_limb_5_col35)) - (xor_col63)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_28 = ((PackedUInt16::from_m31(op0_limb_6_col7))
                ^ (PackedUInt16::from_m31(op1_limb_6_col36)));
            let xor_col64 = xor_tmp_b8fb8_28.as_m31();
            *row[64] = xor_col64;
            *sub_component_inputs.verify_bitwise_xor_9[6] =
                [op0_limb_6_col7, op1_limb_6_col36, xor_col64];
            *lookup_data.verify_bitwise_xor_9_10 =
                [M31_95781001, op0_limb_6_col7, op1_limb_6_col36, xor_col64];

            let and_tmp_b8fb8_30 =
                ((M31_1073741824) * (((op0_limb_6_col7) + (op1_limb_6_col36)) - (xor_col64)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_31 = ((PackedUInt16::from_m31(op0_limb_7_col8))
                ^ (PackedUInt16::from_m31(op1_limb_7_col37)));
            let xor_col65 = xor_tmp_b8fb8_31.as_m31();
            *row[65] = xor_col65;
            *sub_component_inputs.verify_bitwise_xor_9[7] =
                [op0_limb_7_col8, op1_limb_7_col37, xor_col65];
            *lookup_data.verify_bitwise_xor_9_11 =
                [M31_95781001, op0_limb_7_col8, op1_limb_7_col37, xor_col65];

            let and_tmp_b8fb8_33 =
                ((M31_1073741824) * (((op0_limb_7_col8) + (op1_limb_7_col37)) - (xor_col65)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_34 = ((PackedUInt16::from_m31(op0_limb_8_col9))
                ^ (PackedUInt16::from_m31(op1_limb_8_col38)));
            let xor_col66 = xor_tmp_b8fb8_34.as_m31();
            *row[66] = xor_col66;
            *sub_component_inputs.verify_bitwise_xor_9[8] =
                [op0_limb_8_col9, op1_limb_8_col38, xor_col66];
            *lookup_data.verify_bitwise_xor_9_12 =
                [M31_95781001, op0_limb_8_col9, op1_limb_8_col38, xor_col66];

            let and_tmp_b8fb8_36 =
                ((M31_1073741824) * (((op0_limb_8_col9) + (op1_limb_8_col38)) - (xor_col66)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_37 = ((PackedUInt16::from_m31(op0_limb_9_col10))
                ^ (PackedUInt16::from_m31(op1_limb_9_col39)));
            let xor_col67 = xor_tmp_b8fb8_37.as_m31();
            *row[67] = xor_col67;
            *sub_component_inputs.verify_bitwise_xor_9[9] =
                [op0_limb_9_col10, op1_limb_9_col39, xor_col67];
            *lookup_data.verify_bitwise_xor_9_13 =
                [M31_95781001, op0_limb_9_col10, op1_limb_9_col39, xor_col67];

            let and_tmp_b8fb8_39 =
                ((M31_1073741824) * (((op0_limb_9_col10) + (op1_limb_9_col39)) - (xor_col67)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_40 = ((PackedUInt16::from_m31(op0_limb_10_col11))
                ^ (PackedUInt16::from_m31(op1_limb_10_col40)));
            let xor_col68 = xor_tmp_b8fb8_40.as_m31();
            *row[68] = xor_col68;
            *sub_component_inputs.verify_bitwise_xor_9[10] =
                [op0_limb_10_col11, op1_limb_10_col40, xor_col68];
            *lookup_data.verify_bitwise_xor_9_14 = [
                M31_95781001,
                op0_limb_10_col11,
                op1_limb_10_col40,
                xor_col68,
            ];

            let and_tmp_b8fb8_42 =
                ((M31_1073741824) * (((op0_limb_10_col11) + (op1_limb_10_col40)) - (xor_col68)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_43 = ((PackedUInt16::from_m31(op0_limb_11_col12))
                ^ (PackedUInt16::from_m31(op1_limb_11_col41)));
            let xor_col69 = xor_tmp_b8fb8_43.as_m31();
            *row[69] = xor_col69;
            *sub_component_inputs.verify_bitwise_xor_9[11] =
                [op0_limb_11_col12, op1_limb_11_col41, xor_col69];
            *lookup_data.verify_bitwise_xor_9_15 = [
                M31_95781001,
                op0_limb_11_col12,
                op1_limb_11_col41,
                xor_col69,
            ];

            let and_tmp_b8fb8_45 =
                ((M31_1073741824) * (((op0_limb_11_col12) + (op1_limb_11_col41)) - (xor_col69)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_46 = ((PackedUInt16::from_m31(op0_limb_12_col13))
                ^ (PackedUInt16::from_m31(op1_limb_12_col42)));
            let xor_col70 = xor_tmp_b8fb8_46.as_m31();
            *row[70] = xor_col70;
            *sub_component_inputs.verify_bitwise_xor_9[12] =
                [op0_limb_12_col13, op1_limb_12_col42, xor_col70];
            *lookup_data.verify_bitwise_xor_9_16 = [
                M31_95781001,
                op0_limb_12_col13,
                op1_limb_12_col42,
                xor_col70,
            ];

            let and_tmp_b8fb8_48 =
                ((M31_1073741824) * (((op0_limb_12_col13) + (op1_limb_12_col42)) - (xor_col70)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_49 = ((PackedUInt16::from_m31(op0_limb_13_col14))
                ^ (PackedUInt16::from_m31(op1_limb_13_col43)));
            let xor_col71 = xor_tmp_b8fb8_49.as_m31();
            *row[71] = xor_col71;
            *sub_component_inputs.verify_bitwise_xor_9[13] =
                [op0_limb_13_col14, op1_limb_13_col43, xor_col71];
            *lookup_data.verify_bitwise_xor_9_17 = [
                M31_95781001,
                op0_limb_13_col14,
                op1_limb_13_col43,
                xor_col71,
            ];

            let and_tmp_b8fb8_51 =
                ((M31_1073741824) * (((op0_limb_13_col14) + (op1_limb_13_col43)) - (xor_col71)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_52 = ((PackedUInt16::from_m31(op0_limb_14_col15))
                ^ (PackedUInt16::from_m31(op1_limb_14_col44)));
            let xor_col72 = xor_tmp_b8fb8_52.as_m31();
            *row[72] = xor_col72;
            *sub_component_inputs.verify_bitwise_xor_9[14] =
                [op0_limb_14_col15, op1_limb_14_col44, xor_col72];
            *lookup_data.verify_bitwise_xor_9_18 = [
                M31_95781001,
                op0_limb_14_col15,
                op1_limb_14_col44,
                xor_col72,
            ];

            let and_tmp_b8fb8_54 =
                ((M31_1073741824) * (((op0_limb_14_col15) + (op1_limb_14_col44)) - (xor_col72)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_55 = ((PackedUInt16::from_m31(op0_limb_15_col16))
                ^ (PackedUInt16::from_m31(op1_limb_15_col45)));
            let xor_col73 = xor_tmp_b8fb8_55.as_m31();
            *row[73] = xor_col73;
            *sub_component_inputs.verify_bitwise_xor_9[15] =
                [op0_limb_15_col16, op1_limb_15_col45, xor_col73];
            *lookup_data.verify_bitwise_xor_9_19 = [
                M31_95781001,
                op0_limb_15_col16,
                op1_limb_15_col45,
                xor_col73,
            ];

            let and_tmp_b8fb8_57 =
                ((M31_1073741824) * (((op0_limb_15_col16) + (op1_limb_15_col45)) - (xor_col73)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_58 = ((PackedUInt16::from_m31(op0_limb_16_col17))
                ^ (PackedUInt16::from_m31(op1_limb_16_col46)));
            let xor_col74 = xor_tmp_b8fb8_58.as_m31();
            *row[74] = xor_col74;
            *sub_component_inputs.verify_bitwise_xor_9[16] =
                [op0_limb_16_col17, op1_limb_16_col46, xor_col74];
            *lookup_data.verify_bitwise_xor_9_20 = [
                M31_95781001,
                op0_limb_16_col17,
                op1_limb_16_col46,
                xor_col74,
            ];

            let and_tmp_b8fb8_60 =
                ((M31_1073741824) * (((op0_limb_16_col17) + (op1_limb_16_col46)) - (xor_col74)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_61 = ((PackedUInt16::from_m31(op0_limb_17_col18))
                ^ (PackedUInt16::from_m31(op1_limb_17_col47)));
            let xor_col75 = xor_tmp_b8fb8_61.as_m31();
            *row[75] = xor_col75;
            *sub_component_inputs.verify_bitwise_xor_9[17] =
                [op0_limb_17_col18, op1_limb_17_col47, xor_col75];
            *lookup_data.verify_bitwise_xor_9_21 = [
                M31_95781001,
                op0_limb_17_col18,
                op1_limb_17_col47,
                xor_col75,
            ];

            let and_tmp_b8fb8_63 =
                ((M31_1073741824) * (((op0_limb_17_col18) + (op1_limb_17_col47)) - (xor_col75)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_64 = ((PackedUInt16::from_m31(op0_limb_18_col19))
                ^ (PackedUInt16::from_m31(op1_limb_18_col48)));
            let xor_col76 = xor_tmp_b8fb8_64.as_m31();
            *row[76] = xor_col76;
            *sub_component_inputs.verify_bitwise_xor_9[18] =
                [op0_limb_18_col19, op1_limb_18_col48, xor_col76];
            *lookup_data.verify_bitwise_xor_9_22 = [
                M31_95781001,
                op0_limb_18_col19,
                op1_limb_18_col48,
                xor_col76,
            ];

            let and_tmp_b8fb8_66 =
                ((M31_1073741824) * (((op0_limb_18_col19) + (op1_limb_18_col48)) - (xor_col76)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_67 = ((PackedUInt16::from_m31(op0_limb_19_col20))
                ^ (PackedUInt16::from_m31(op1_limb_19_col49)));
            let xor_col77 = xor_tmp_b8fb8_67.as_m31();
            *row[77] = xor_col77;
            *sub_component_inputs.verify_bitwise_xor_9[19] =
                [op0_limb_19_col20, op1_limb_19_col49, xor_col77];
            *lookup_data.verify_bitwise_xor_9_23 = [
                M31_95781001,
                op0_limb_19_col20,
                op1_limb_19_col49,
                xor_col77,
            ];

            let and_tmp_b8fb8_69 =
                ((M31_1073741824) * (((op0_limb_19_col20) + (op1_limb_19_col49)) - (xor_col77)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_70 = ((PackedUInt16::from_m31(op0_limb_20_col21))
                ^ (PackedUInt16::from_m31(op1_limb_20_col50)));
            let xor_col78 = xor_tmp_b8fb8_70.as_m31();
            *row[78] = xor_col78;
            *sub_component_inputs.verify_bitwise_xor_9[20] =
                [op0_limb_20_col21, op1_limb_20_col50, xor_col78];
            *lookup_data.verify_bitwise_xor_9_24 = [
                M31_95781001,
                op0_limb_20_col21,
                op1_limb_20_col50,
                xor_col78,
            ];

            let and_tmp_b8fb8_72 =
                ((M31_1073741824) * (((op0_limb_20_col21) + (op1_limb_20_col50)) - (xor_col78)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_73 = ((PackedUInt16::from_m31(op0_limb_21_col22))
                ^ (PackedUInt16::from_m31(op1_limb_21_col51)));
            let xor_col79 = xor_tmp_b8fb8_73.as_m31();
            *row[79] = xor_col79;
            *sub_component_inputs.verify_bitwise_xor_9[21] =
                [op0_limb_21_col22, op1_limb_21_col51, xor_col79];
            *lookup_data.verify_bitwise_xor_9_25 = [
                M31_95781001,
                op0_limb_21_col22,
                op1_limb_21_col51,
                xor_col79,
            ];

            let and_tmp_b8fb8_75 =
                ((M31_1073741824) * (((op0_limb_21_col22) + (op1_limb_21_col51)) - (xor_col79)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_76 = ((PackedUInt16::from_m31(op0_limb_22_col23))
                ^ (PackedUInt16::from_m31(op1_limb_22_col52)));
            let xor_col80 = xor_tmp_b8fb8_76.as_m31();
            *row[80] = xor_col80;
            *sub_component_inputs.verify_bitwise_xor_9[22] =
                [op0_limb_22_col23, op1_limb_22_col52, xor_col80];
            *lookup_data.verify_bitwise_xor_9_26 = [
                M31_95781001,
                op0_limb_22_col23,
                op1_limb_22_col52,
                xor_col80,
            ];

            let and_tmp_b8fb8_78 =
                ((M31_1073741824) * (((op0_limb_22_col23) + (op1_limb_22_col52)) - (xor_col80)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_79 = ((PackedUInt16::from_m31(op0_limb_23_col24))
                ^ (PackedUInt16::from_m31(op1_limb_23_col53)));
            let xor_col81 = xor_tmp_b8fb8_79.as_m31();
            *row[81] = xor_col81;
            *sub_component_inputs.verify_bitwise_xor_9[23] =
                [op0_limb_23_col24, op1_limb_23_col53, xor_col81];
            *lookup_data.verify_bitwise_xor_9_27 = [
                M31_95781001,
                op0_limb_23_col24,
                op1_limb_23_col53,
                xor_col81,
            ];

            let and_tmp_b8fb8_81 =
                ((M31_1073741824) * (((op0_limb_23_col24) + (op1_limb_23_col53)) - (xor_col81)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_82 = ((PackedUInt16::from_m31(op0_limb_24_col25))
                ^ (PackedUInt16::from_m31(op1_limb_24_col54)));
            let xor_col82 = xor_tmp_b8fb8_82.as_m31();
            *row[82] = xor_col82;
            *sub_component_inputs.verify_bitwise_xor_9[24] =
                [op0_limb_24_col25, op1_limb_24_col54, xor_col82];
            *lookup_data.verify_bitwise_xor_9_28 = [
                M31_95781001,
                op0_limb_24_col25,
                op1_limb_24_col54,
                xor_col82,
            ];

            let and_tmp_b8fb8_84 =
                ((M31_1073741824) * (((op0_limb_24_col25) + (op1_limb_24_col54)) - (xor_col82)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_85 = ((PackedUInt16::from_m31(op0_limb_25_col26))
                ^ (PackedUInt16::from_m31(op1_limb_25_col55)));
            let xor_col83 = xor_tmp_b8fb8_85.as_m31();
            *row[83] = xor_col83;
            *sub_component_inputs.verify_bitwise_xor_9[25] =
                [op0_limb_25_col26, op1_limb_25_col55, xor_col83];
            *lookup_data.verify_bitwise_xor_9_29 = [
                M31_95781001,
                op0_limb_25_col26,
                op1_limb_25_col55,
                xor_col83,
            ];

            let and_tmp_b8fb8_87 =
                ((M31_1073741824) * (((op0_limb_25_col26) + (op1_limb_25_col55)) - (xor_col83)));

            // Bitwise Xor Num Bits 9.

            let xor_tmp_b8fb8_88 = ((PackedUInt16::from_m31(op0_limb_26_col27))
                ^ (PackedUInt16::from_m31(op1_limb_26_col56)));
            let xor_col84 = xor_tmp_b8fb8_88.as_m31();
            *row[84] = xor_col84;
            *sub_component_inputs.verify_bitwise_xor_9[26] =
                [op0_limb_26_col27, op1_limb_26_col56, xor_col84];
            *lookup_data.verify_bitwise_xor_9_30 = [
                M31_95781001,
                op0_limb_26_col27,
                op1_limb_26_col56,
                xor_col84,
            ];

            let and_tmp_b8fb8_90 =
                ((M31_1073741824) * (((op0_limb_26_col27) + (op1_limb_26_col56)) - (xor_col84)));

            // Bitwise Xor Num Bits 8.

            let xor_tmp_b8fb8_91 = ((PackedUInt16::from_m31(op0_limb_27_col28))
                ^ (PackedUInt16::from_m31(op1_limb_27_col57)));
            let xor_col85 = xor_tmp_b8fb8_91.as_m31();
            *row[85] = xor_col85;
            *sub_component_inputs.verify_bitwise_xor_8[0] =
                [op0_limb_27_col28, op1_limb_27_col57, xor_col85];
            *lookup_data.verify_bitwise_xor_8_31 = [
                M31_112558620,
                op0_limb_27_col28,
                op1_limb_27_col57,
                xor_col85,
            ];

            let and_tmp_b8fb8_93 =
                ((M31_1073741824) * (((op0_limb_27_col28) + (op1_limb_27_col57)) - (xor_col85)));

            // Mem Verify.

            // Read Id.

            let memory_address_to_id_value_tmp_b8fb8_94 = memory_address_to_id_state.deduce_output(
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_2)),
            );
            let and_id_col86 = memory_address_to_id_value_tmp_b8fb8_94;
            *row[86] = and_id_col86;
            *sub_component_inputs.memory_address_to_id[2] =
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_2));
            *lookup_data.memory_address_to_id_32 = [
                M31_1444891767,
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_2)),
                and_id_col86,
            ];

            *sub_component_inputs.memory_id_to_big[2] = and_id_col86;
            *lookup_data.memory_id_to_big_33 = [
                M31_1662111297,
                and_id_col86,
                and_tmp_b8fb8_12,
                and_tmp_b8fb8_15,
                and_tmp_b8fb8_18,
                and_tmp_b8fb8_21,
                and_tmp_b8fb8_24,
                and_tmp_b8fb8_27,
                and_tmp_b8fb8_30,
                and_tmp_b8fb8_33,
                and_tmp_b8fb8_36,
                and_tmp_b8fb8_39,
                and_tmp_b8fb8_42,
                and_tmp_b8fb8_45,
                and_tmp_b8fb8_48,
                and_tmp_b8fb8_51,
                and_tmp_b8fb8_54,
                and_tmp_b8fb8_57,
                and_tmp_b8fb8_60,
                and_tmp_b8fb8_63,
                and_tmp_b8fb8_66,
                and_tmp_b8fb8_69,
                and_tmp_b8fb8_72,
                and_tmp_b8fb8_75,
                and_tmp_b8fb8_78,
                and_tmp_b8fb8_81,
                and_tmp_b8fb8_84,
                and_tmp_b8fb8_87,
                and_tmp_b8fb8_90,
                and_tmp_b8fb8_93,
            ];

            // Mem Verify.

            // Read Id.

            let memory_address_to_id_value_tmp_b8fb8_96 = memory_address_to_id_state.deduce_output(
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_3)),
            );
            let xor_id_col87 = memory_address_to_id_value_tmp_b8fb8_96;
            *row[87] = xor_id_col87;
            *sub_component_inputs.memory_address_to_id[3] =
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_3));
            *lookup_data.memory_address_to_id_34 = [
                M31_1444891767,
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_3)),
                xor_id_col87,
            ];

            *sub_component_inputs.memory_id_to_big[3] = xor_id_col87;
            *lookup_data.memory_id_to_big_35 = [
                M31_1662111297,
                xor_id_col87,
                xor_col58,
                xor_col59,
                xor_col60,
                xor_col61,
                xor_col62,
                xor_col63,
                xor_col64,
                xor_col65,
                xor_col66,
                xor_col67,
                xor_col68,
                xor_col69,
                xor_col70,
                xor_col71,
                xor_col72,
                xor_col73,
                xor_col74,
                xor_col75,
                xor_col76,
                xor_col77,
                xor_col78,
                xor_col79,
                xor_col80,
                xor_col81,
                xor_col82,
                xor_col83,
                xor_col84,
                xor_col85,
            ];

            // Mem Verify.

            // Read Id.

            let memory_address_to_id_value_tmp_b8fb8_98 = memory_address_to_id_state.deduce_output(
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_4)),
            );
            let or_id_col88 = memory_address_to_id_value_tmp_b8fb8_98;
            *row[88] = or_id_col88;
            *sub_component_inputs.memory_address_to_id[4] =
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_4));
            *lookup_data.memory_address_to_id_36 = [
                M31_1444891767,
                (((PackedM31::broadcast(M31::from(bitwise_builtin_segment_start)))
                    + ((seq) * (M31_5)))
                    + (M31_4)),
                or_id_col88,
            ];

            *sub_component_inputs.memory_id_to_big[4] = or_id_col88;
            *lookup_data.memory_id_to_big_37 = [
                M31_1662111297,
                or_id_col88,
                ((and_tmp_b8fb8_12) + (xor_col58)),
                ((and_tmp_b8fb8_15) + (xor_col59)),
                ((and_tmp_b8fb8_18) + (xor_col60)),
                ((and_tmp_b8fb8_21) + (xor_col61)),
                ((and_tmp_b8fb8_24) + (xor_col62)),
                ((and_tmp_b8fb8_27) + (xor_col63)),
                ((and_tmp_b8fb8_30) + (xor_col64)),
                ((and_tmp_b8fb8_33) + (xor_col65)),
                ((and_tmp_b8fb8_36) + (xor_col66)),
                ((and_tmp_b8fb8_39) + (xor_col67)),
                ((and_tmp_b8fb8_42) + (xor_col68)),
                ((and_tmp_b8fb8_45) + (xor_col69)),
                ((and_tmp_b8fb8_48) + (xor_col70)),
                ((and_tmp_b8fb8_51) + (xor_col71)),
                ((and_tmp_b8fb8_54) + (xor_col72)),
                ((and_tmp_b8fb8_57) + (xor_col73)),
                ((and_tmp_b8fb8_60) + (xor_col74)),
                ((and_tmp_b8fb8_63) + (xor_col75)),
                ((and_tmp_b8fb8_66) + (xor_col76)),
                ((and_tmp_b8fb8_69) + (xor_col77)),
                ((and_tmp_b8fb8_72) + (xor_col78)),
                ((and_tmp_b8fb8_75) + (xor_col79)),
                ((and_tmp_b8fb8_78) + (xor_col80)),
                ((and_tmp_b8fb8_81) + (xor_col81)),
                ((and_tmp_b8fb8_84) + (xor_col82)),
                ((and_tmp_b8fb8_87) + (xor_col83)),
                ((and_tmp_b8fb8_90) + (xor_col84)),
                ((and_tmp_b8fb8_93) + (xor_col85)),
            ];

            *lookup_data.mults_0 = M31_1;
        });

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `bitwise_builtin` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     memory_address_to_id_0[3] 0..2
//     memory_id_to_big_1[30] 3..32
//     memory_address_to_id_2[3] 33..35
//     memory_id_to_big_3[30] 36..65
//     verify_bitwise_xor_9_4[4] 66..69
//     verify_bitwise_xor_9_5[4] 70..73
//     verify_bitwise_xor_9_6[4] 74..77
//     verify_bitwise_xor_9_7[4] 78..81
//     verify_bitwise_xor_9_8[4] 82..85
//     verify_bitwise_xor_9_9[4] 86..89
//     verify_bitwise_xor_9_10[4] 90..93
//     verify_bitwise_xor_9_11[4] 94..97
//     verify_bitwise_xor_9_12[4] 98..101
//     verify_bitwise_xor_9_13[4] 102..105
//     verify_bitwise_xor_9_14[4] 106..109
//     verify_bitwise_xor_9_15[4] 110..113
//     verify_bitwise_xor_9_16[4] 114..117
//     verify_bitwise_xor_9_17[4] 118..121
//     verify_bitwise_xor_9_18[4] 122..125
//     verify_bitwise_xor_9_19[4] 126..129
//     verify_bitwise_xor_9_20[4] 130..133
//     verify_bitwise_xor_9_21[4] 134..137
//     verify_bitwise_xor_9_22[4] 138..141
//     verify_bitwise_xor_9_23[4] 142..145
//     verify_bitwise_xor_9_24[4] 146..149
//     verify_bitwise_xor_9_25[4] 150..153
//     verify_bitwise_xor_9_26[4] 154..157
//     verify_bitwise_xor_9_27[4] 158..161
//     verify_bitwise_xor_9_28[4] 162..165
//     verify_bitwise_xor_9_29[4] 166..169
//     verify_bitwise_xor_9_30[4] 170..173
//     verify_bitwise_xor_8_31[4] 174..177
//     memory_address_to_id_32[3] 178..180
//     memory_id_to_big_33[30] 181..210
//     memory_address_to_id_34[3] 211..213
//     memory_id_to_big_35[30] 214..243
//     memory_address_to_id_36[3] 244..246
//     memory_id_to_big_37[30] 247..276
//     mults_0 277
//     (278 words)
//   SUB-INPUT words:
//     memory_address_to_id[0] 0
//     memory_address_to_id[1] 1
//     memory_address_to_id[2] 2
//     memory_address_to_id[3] 3
//     memory_address_to_id[4] 4
//     memory_id_to_big[0] 5
//     memory_id_to_big[1] 6
//     memory_id_to_big[2] 7
//     memory_id_to_big[3] 8
//     memory_id_to_big[4] 9
//     verify_bitwise_xor_9[0] 10..12
//     verify_bitwise_xor_9[1] 13..15
//     verify_bitwise_xor_9[2] 16..18
//     verify_bitwise_xor_9[3] 19..21
//     verify_bitwise_xor_9[4] 22..24
//     verify_bitwise_xor_9[5] 25..27
//     verify_bitwise_xor_9[6] 28..30
//     verify_bitwise_xor_9[7] 31..33
//     verify_bitwise_xor_9[8] 34..36
//     verify_bitwise_xor_9[9] 37..39
//     verify_bitwise_xor_9[10] 40..42
//     verify_bitwise_xor_9[11] 43..45
//     verify_bitwise_xor_9[12] 46..48
//     verify_bitwise_xor_9[13] 49..51
//     verify_bitwise_xor_9[14] 52..54
//     verify_bitwise_xor_9[15] 55..57
//     verify_bitwise_xor_9[16] 58..60
//     verify_bitwise_xor_9[17] 61..63
//     verify_bitwise_xor_9[18] 64..66
//     verify_bitwise_xor_9[19] 67..69
//     verify_bitwise_xor_9[20] 70..72
//     verify_bitwise_xor_9[21] 73..75
//     verify_bitwise_xor_9[22] 76..78
//     verify_bitwise_xor_9[23] 79..81
//     verify_bitwise_xor_9[24] 82..84
//     verify_bitwise_xor_9[25] 85..87
//     verify_bitwise_xor_9[26] 88..90
//     verify_bitwise_xor_8[0] 91..93
//     (94 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 278;
pub(crate) const N_SUB_INPUT_WORDS: usize = 94;

/// The per-row `bitwise_builtin` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn bitwise_builtin_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_4 = eval.m31_const(4);
    let m31_5 = eval.m31_const(5);
    let m31_95781001 = eval.m31_const(95781001);
    let m31_112558620 = eval.m31_const(112558620);
    let m31_1073741824 = eval.m31_const(1073741824);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let seq = eval.iota();
    let wg_v0 = eval.input(0);
    let wg_v1 = eval.m31_mul(seq, m31_5);
    let wg_v2 = eval.m31_add(wg_v0, wg_v1);
    let memory_address_to_id_value_tmp_b8fb8_0 = eval.mem_addr_to_id(wg_v2);
    let op0_id_col0 = memory_address_to_id_value_tmp_b8fb8_0;
    eval.set_col(0, op0_id_col0);
    let wg_v3 = eval.input(0);
    let wg_v4 = eval.m31_mul(seq, m31_5);
    let wg_v5 = eval.m31_add(wg_v3, wg_v4);
    eval.set_sub_input_word(0, wg_v5);
    eval.set_lookup_word(0, m31_1444891767);
    let wg_v6 = eval.input(0);
    let wg_v7 = eval.m31_mul(seq, m31_5);
    let wg_v8 = eval.m31_add(wg_v6, wg_v7);
    eval.set_lookup_word(1, wg_v8);
    eval.set_lookup_word(2, op0_id_col0);
    let memory_id_to_big_value_tmp_b8fb8_2 = eval.mem_id_to_value(op0_id_col0);
    let op0_limb_0_col1 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 0);
    eval.set_col(1, op0_limb_0_col1);
    let op0_limb_1_col2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 1);
    eval.set_col(2, op0_limb_1_col2);
    let op0_limb_2_col3 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 2);
    eval.set_col(3, op0_limb_2_col3);
    let op0_limb_3_col4 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 3);
    eval.set_col(4, op0_limb_3_col4);
    let op0_limb_4_col5 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 4);
    eval.set_col(5, op0_limb_4_col5);
    let op0_limb_5_col6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 5);
    eval.set_col(6, op0_limb_5_col6);
    let op0_limb_6_col7 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 6);
    eval.set_col(7, op0_limb_6_col7);
    let op0_limb_7_col8 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 7);
    eval.set_col(8, op0_limb_7_col8);
    let op0_limb_8_col9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 8);
    eval.set_col(9, op0_limb_8_col9);
    let op0_limb_9_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 9);
    eval.set_col(10, op0_limb_9_col10);
    let op0_limb_10_col11 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 10);
    eval.set_col(11, op0_limb_10_col11);
    let op0_limb_11_col12 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 11);
    eval.set_col(12, op0_limb_11_col12);
    let op0_limb_12_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 12);
    eval.set_col(13, op0_limb_12_col13);
    let op0_limb_13_col14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 13);
    eval.set_col(14, op0_limb_13_col14);
    let op0_limb_14_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 14);
    eval.set_col(15, op0_limb_14_col15);
    let op0_limb_15_col16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 15);
    eval.set_col(16, op0_limb_15_col16);
    let op0_limb_16_col17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 16);
    eval.set_col(17, op0_limb_16_col17);
    let op0_limb_17_col18 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 17);
    eval.set_col(18, op0_limb_17_col18);
    let op0_limb_18_col19 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 18);
    eval.set_col(19, op0_limb_18_col19);
    let op0_limb_19_col20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 19);
    eval.set_col(20, op0_limb_19_col20);
    let op0_limb_20_col21 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 20);
    eval.set_col(21, op0_limb_20_col21);
    let op0_limb_21_col22 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 21);
    eval.set_col(22, op0_limb_21_col22);
    let op0_limb_22_col23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 22);
    eval.set_col(23, op0_limb_22_col23);
    let op0_limb_23_col24 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 23);
    eval.set_col(24, op0_limb_23_col24);
    let op0_limb_24_col25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 24);
    eval.set_col(25, op0_limb_24_col25);
    let op0_limb_25_col26 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 25);
    eval.set_col(26, op0_limb_25_col26);
    let op0_limb_26_col27 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 26);
    eval.set_col(27, op0_limb_26_col27);
    let op0_limb_27_col28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_2.clone(), 27);
    eval.set_col(28, op0_limb_27_col28);
    eval.set_sub_input_word(5, op0_id_col0);
    eval.set_lookup_word(3, m31_1662111297);
    eval.set_lookup_word(4, op0_id_col0);
    eval.set_lookup_word(5, op0_limb_0_col1);
    eval.set_lookup_word(6, op0_limb_1_col2);
    eval.set_lookup_word(7, op0_limb_2_col3);
    eval.set_lookup_word(8, op0_limb_3_col4);
    eval.set_lookup_word(9, op0_limb_4_col5);
    eval.set_lookup_word(10, op0_limb_5_col6);
    eval.set_lookup_word(11, op0_limb_6_col7);
    eval.set_lookup_word(12, op0_limb_7_col8);
    eval.set_lookup_word(13, op0_limb_8_col9);
    eval.set_lookup_word(14, op0_limb_9_col10);
    eval.set_lookup_word(15, op0_limb_10_col11);
    eval.set_lookup_word(16, op0_limb_11_col12);
    eval.set_lookup_word(17, op0_limb_12_col13);
    eval.set_lookup_word(18, op0_limb_13_col14);
    eval.set_lookup_word(19, op0_limb_14_col15);
    eval.set_lookup_word(20, op0_limb_15_col16);
    eval.set_lookup_word(21, op0_limb_16_col17);
    eval.set_lookup_word(22, op0_limb_17_col18);
    eval.set_lookup_word(23, op0_limb_18_col19);
    eval.set_lookup_word(24, op0_limb_19_col20);
    eval.set_lookup_word(25, op0_limb_20_col21);
    eval.set_lookup_word(26, op0_limb_21_col22);
    eval.set_lookup_word(27, op0_limb_22_col23);
    eval.set_lookup_word(28, op0_limb_23_col24);
    eval.set_lookup_word(29, op0_limb_24_col25);
    eval.set_lookup_word(30, op0_limb_25_col26);
    eval.set_lookup_word(31, op0_limb_26_col27);
    eval.set_lookup_word(32, op0_limb_27_col28);
    let read_positive_known_id_num_bits_252_output_tmp_b8fb8_3 = eval.felt_from_limbs([
        op0_limb_0_col1,
        op0_limb_1_col2,
        op0_limb_2_col3,
        op0_limb_3_col4,
        op0_limb_4_col5,
        op0_limb_5_col6,
        op0_limb_6_col7,
        op0_limb_7_col8,
        op0_limb_8_col9,
        op0_limb_9_col10,
        op0_limb_10_col11,
        op0_limb_11_col12,
        op0_limb_12_col13,
        op0_limb_13_col14,
        op0_limb_14_col15,
        op0_limb_15_col16,
        op0_limb_16_col17,
        op0_limb_17_col18,
        op0_limb_18_col19,
        op0_limb_19_col20,
        op0_limb_20_col21,
        op0_limb_21_col22,
        op0_limb_22_col23,
        op0_limb_23_col24,
        op0_limb_24_col25,
        op0_limb_25_col26,
        op0_limb_26_col27,
        op0_limb_27_col28,
    ]);
    let read_positive_num_bits_252_output_tmp_b8fb8_4 = (
        read_positive_known_id_num_bits_252_output_tmp_b8fb8_3.clone(),
        op0_id_col0,
    );
    let wg_v9 = eval.input(0);
    let wg_v10 = eval.m31_mul(seq, m31_5);
    let wg_v11 = eval.m31_add(wg_v9, wg_v10);
    let wg_v12 = eval.m31_add(wg_v11, m31_1);
    let memory_address_to_id_value_tmp_b8fb8_5 = eval.mem_addr_to_id(wg_v12);
    let op1_id_col29 = memory_address_to_id_value_tmp_b8fb8_5;
    eval.set_col(29, op1_id_col29);
    let wg_v13 = eval.input(0);
    let wg_v14 = eval.m31_mul(seq, m31_5);
    let wg_v15 = eval.m31_add(wg_v13, wg_v14);
    let wg_v16 = eval.m31_add(wg_v15, m31_1);
    eval.set_sub_input_word(1, wg_v16);
    eval.set_lookup_word(33, m31_1444891767);
    let wg_v17 = eval.input(0);
    let wg_v18 = eval.m31_mul(seq, m31_5);
    let wg_v19 = eval.m31_add(wg_v17, wg_v18);
    let wg_v20 = eval.m31_add(wg_v19, m31_1);
    eval.set_lookup_word(34, wg_v20);
    eval.set_lookup_word(35, op1_id_col29);
    let memory_id_to_big_value_tmp_b8fb8_7 = eval.mem_id_to_value(op1_id_col29);
    let op1_limb_0_col30 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 0);
    eval.set_col(30, op1_limb_0_col30);
    let op1_limb_1_col31 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 1);
    eval.set_col(31, op1_limb_1_col31);
    let op1_limb_2_col32 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 2);
    eval.set_col(32, op1_limb_2_col32);
    let op1_limb_3_col33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 3);
    eval.set_col(33, op1_limb_3_col33);
    let op1_limb_4_col34 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 4);
    eval.set_col(34, op1_limb_4_col34);
    let op1_limb_5_col35 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 5);
    eval.set_col(35, op1_limb_5_col35);
    let op1_limb_6_col36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 6);
    eval.set_col(36, op1_limb_6_col36);
    let op1_limb_7_col37 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 7);
    eval.set_col(37, op1_limb_7_col37);
    let op1_limb_8_col38 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 8);
    eval.set_col(38, op1_limb_8_col38);
    let op1_limb_9_col39 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 9);
    eval.set_col(39, op1_limb_9_col39);
    let op1_limb_10_col40 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 10);
    eval.set_col(40, op1_limb_10_col40);
    let op1_limb_11_col41 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 11);
    eval.set_col(41, op1_limb_11_col41);
    let op1_limb_12_col42 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 12);
    eval.set_col(42, op1_limb_12_col42);
    let op1_limb_13_col43 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 13);
    eval.set_col(43, op1_limb_13_col43);
    let op1_limb_14_col44 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 14);
    eval.set_col(44, op1_limb_14_col44);
    let op1_limb_15_col45 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 15);
    eval.set_col(45, op1_limb_15_col45);
    let op1_limb_16_col46 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 16);
    eval.set_col(46, op1_limb_16_col46);
    let op1_limb_17_col47 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 17);
    eval.set_col(47, op1_limb_17_col47);
    let op1_limb_18_col48 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 18);
    eval.set_col(48, op1_limb_18_col48);
    let op1_limb_19_col49 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 19);
    eval.set_col(49, op1_limb_19_col49);
    let op1_limb_20_col50 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 20);
    eval.set_col(50, op1_limb_20_col50);
    let op1_limb_21_col51 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 21);
    eval.set_col(51, op1_limb_21_col51);
    let op1_limb_22_col52 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 22);
    eval.set_col(52, op1_limb_22_col52);
    let op1_limb_23_col53 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 23);
    eval.set_col(53, op1_limb_23_col53);
    let op1_limb_24_col54 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 24);
    eval.set_col(54, op1_limb_24_col54);
    let op1_limb_25_col55 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 25);
    eval.set_col(55, op1_limb_25_col55);
    let op1_limb_26_col56 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 26);
    eval.set_col(56, op1_limb_26_col56);
    let op1_limb_27_col57 = eval.felt_get_m31(&memory_id_to_big_value_tmp_b8fb8_7.clone(), 27);
    eval.set_col(57, op1_limb_27_col57);
    eval.set_sub_input_word(6, op1_id_col29);
    eval.set_lookup_word(36, m31_1662111297);
    eval.set_lookup_word(37, op1_id_col29);
    eval.set_lookup_word(38, op1_limb_0_col30);
    eval.set_lookup_word(39, op1_limb_1_col31);
    eval.set_lookup_word(40, op1_limb_2_col32);
    eval.set_lookup_word(41, op1_limb_3_col33);
    eval.set_lookup_word(42, op1_limb_4_col34);
    eval.set_lookup_word(43, op1_limb_5_col35);
    eval.set_lookup_word(44, op1_limb_6_col36);
    eval.set_lookup_word(45, op1_limb_7_col37);
    eval.set_lookup_word(46, op1_limb_8_col38);
    eval.set_lookup_word(47, op1_limb_9_col39);
    eval.set_lookup_word(48, op1_limb_10_col40);
    eval.set_lookup_word(49, op1_limb_11_col41);
    eval.set_lookup_word(50, op1_limb_12_col42);
    eval.set_lookup_word(51, op1_limb_13_col43);
    eval.set_lookup_word(52, op1_limb_14_col44);
    eval.set_lookup_word(53, op1_limb_15_col45);
    eval.set_lookup_word(54, op1_limb_16_col46);
    eval.set_lookup_word(55, op1_limb_17_col47);
    eval.set_lookup_word(56, op1_limb_18_col48);
    eval.set_lookup_word(57, op1_limb_19_col49);
    eval.set_lookup_word(58, op1_limb_20_col50);
    eval.set_lookup_word(59, op1_limb_21_col51);
    eval.set_lookup_word(60, op1_limb_22_col52);
    eval.set_lookup_word(61, op1_limb_23_col53);
    eval.set_lookup_word(62, op1_limb_24_col54);
    eval.set_lookup_word(63, op1_limb_25_col55);
    eval.set_lookup_word(64, op1_limb_26_col56);
    eval.set_lookup_word(65, op1_limb_27_col57);
    let read_positive_known_id_num_bits_252_output_tmp_b8fb8_8 = eval.felt_from_limbs([
        op1_limb_0_col30,
        op1_limb_1_col31,
        op1_limb_2_col32,
        op1_limb_3_col33,
        op1_limb_4_col34,
        op1_limb_5_col35,
        op1_limb_6_col36,
        op1_limb_7_col37,
        op1_limb_8_col38,
        op1_limb_9_col39,
        op1_limb_10_col40,
        op1_limb_11_col41,
        op1_limb_12_col42,
        op1_limb_13_col43,
        op1_limb_14_col44,
        op1_limb_15_col45,
        op1_limb_16_col46,
        op1_limb_17_col47,
        op1_limb_18_col48,
        op1_limb_19_col49,
        op1_limb_20_col50,
        op1_limb_21_col51,
        op1_limb_22_col52,
        op1_limb_23_col53,
        op1_limb_24_col54,
        op1_limb_25_col55,
        op1_limb_26_col56,
        op1_limb_27_col57,
    ]);
    let read_positive_num_bits_252_output_tmp_b8fb8_9 = (
        read_positive_known_id_num_bits_252_output_tmp_b8fb8_8.clone(),
        op1_id_col29,
    );
    let wg_v21 = eval.u16_from_m31(op0_limb_0_col1);
    let wg_v22 = eval.u16_from_m31(op1_limb_0_col30);
    let xor_tmp_b8fb8_10 = eval.u16_xor(wg_v21, wg_v22);
    let xor_col58 = eval.u16_as_m31(xor_tmp_b8fb8_10);
    eval.set_col(58, xor_col58);
    eval.set_sub_input_word(10, op0_limb_0_col1);
    eval.set_sub_input_word(11, op1_limb_0_col30);
    eval.set_sub_input_word(12, xor_col58);
    eval.set_lookup_word(66, m31_95781001);
    eval.set_lookup_word(67, op0_limb_0_col1);
    eval.set_lookup_word(68, op1_limb_0_col30);
    eval.set_lookup_word(69, xor_col58);
    let wg_v23 = eval.m31_add(op0_limb_0_col1, op1_limb_0_col30);
    let wg_v24 = eval.m31_sub(wg_v23, xor_col58);
    let and_tmp_b8fb8_12 = eval.m31_mul(m31_1073741824, wg_v24);
    let wg_v25 = eval.u16_from_m31(op0_limb_1_col2);
    let wg_v26 = eval.u16_from_m31(op1_limb_1_col31);
    let xor_tmp_b8fb8_13 = eval.u16_xor(wg_v25, wg_v26);
    let xor_col59 = eval.u16_as_m31(xor_tmp_b8fb8_13);
    eval.set_col(59, xor_col59);
    eval.set_sub_input_word(13, op0_limb_1_col2);
    eval.set_sub_input_word(14, op1_limb_1_col31);
    eval.set_sub_input_word(15, xor_col59);
    eval.set_lookup_word(70, m31_95781001);
    eval.set_lookup_word(71, op0_limb_1_col2);
    eval.set_lookup_word(72, op1_limb_1_col31);
    eval.set_lookup_word(73, xor_col59);
    let wg_v27 = eval.m31_add(op0_limb_1_col2, op1_limb_1_col31);
    let wg_v28 = eval.m31_sub(wg_v27, xor_col59);
    let and_tmp_b8fb8_15 = eval.m31_mul(m31_1073741824, wg_v28);
    let wg_v29 = eval.u16_from_m31(op0_limb_2_col3);
    let wg_v30 = eval.u16_from_m31(op1_limb_2_col32);
    let xor_tmp_b8fb8_16 = eval.u16_xor(wg_v29, wg_v30);
    let xor_col60 = eval.u16_as_m31(xor_tmp_b8fb8_16);
    eval.set_col(60, xor_col60);
    eval.set_sub_input_word(16, op0_limb_2_col3);
    eval.set_sub_input_word(17, op1_limb_2_col32);
    eval.set_sub_input_word(18, xor_col60);
    eval.set_lookup_word(74, m31_95781001);
    eval.set_lookup_word(75, op0_limb_2_col3);
    eval.set_lookup_word(76, op1_limb_2_col32);
    eval.set_lookup_word(77, xor_col60);
    let wg_v31 = eval.m31_add(op0_limb_2_col3, op1_limb_2_col32);
    let wg_v32 = eval.m31_sub(wg_v31, xor_col60);
    let and_tmp_b8fb8_18 = eval.m31_mul(m31_1073741824, wg_v32);
    let wg_v33 = eval.u16_from_m31(op0_limb_3_col4);
    let wg_v34 = eval.u16_from_m31(op1_limb_3_col33);
    let xor_tmp_b8fb8_19 = eval.u16_xor(wg_v33, wg_v34);
    let xor_col61 = eval.u16_as_m31(xor_tmp_b8fb8_19);
    eval.set_col(61, xor_col61);
    eval.set_sub_input_word(19, op0_limb_3_col4);
    eval.set_sub_input_word(20, op1_limb_3_col33);
    eval.set_sub_input_word(21, xor_col61);
    eval.set_lookup_word(78, m31_95781001);
    eval.set_lookup_word(79, op0_limb_3_col4);
    eval.set_lookup_word(80, op1_limb_3_col33);
    eval.set_lookup_word(81, xor_col61);
    let wg_v35 = eval.m31_add(op0_limb_3_col4, op1_limb_3_col33);
    let wg_v36 = eval.m31_sub(wg_v35, xor_col61);
    let and_tmp_b8fb8_21 = eval.m31_mul(m31_1073741824, wg_v36);
    let wg_v37 = eval.u16_from_m31(op0_limb_4_col5);
    let wg_v38 = eval.u16_from_m31(op1_limb_4_col34);
    let xor_tmp_b8fb8_22 = eval.u16_xor(wg_v37, wg_v38);
    let xor_col62 = eval.u16_as_m31(xor_tmp_b8fb8_22);
    eval.set_col(62, xor_col62);
    eval.set_sub_input_word(22, op0_limb_4_col5);
    eval.set_sub_input_word(23, op1_limb_4_col34);
    eval.set_sub_input_word(24, xor_col62);
    eval.set_lookup_word(82, m31_95781001);
    eval.set_lookup_word(83, op0_limb_4_col5);
    eval.set_lookup_word(84, op1_limb_4_col34);
    eval.set_lookup_word(85, xor_col62);
    let wg_v39 = eval.m31_add(op0_limb_4_col5, op1_limb_4_col34);
    let wg_v40 = eval.m31_sub(wg_v39, xor_col62);
    let and_tmp_b8fb8_24 = eval.m31_mul(m31_1073741824, wg_v40);
    let wg_v41 = eval.u16_from_m31(op0_limb_5_col6);
    let wg_v42 = eval.u16_from_m31(op1_limb_5_col35);
    let xor_tmp_b8fb8_25 = eval.u16_xor(wg_v41, wg_v42);
    let xor_col63 = eval.u16_as_m31(xor_tmp_b8fb8_25);
    eval.set_col(63, xor_col63);
    eval.set_sub_input_word(25, op0_limb_5_col6);
    eval.set_sub_input_word(26, op1_limb_5_col35);
    eval.set_sub_input_word(27, xor_col63);
    eval.set_lookup_word(86, m31_95781001);
    eval.set_lookup_word(87, op0_limb_5_col6);
    eval.set_lookup_word(88, op1_limb_5_col35);
    eval.set_lookup_word(89, xor_col63);
    let wg_v43 = eval.m31_add(op0_limb_5_col6, op1_limb_5_col35);
    let wg_v44 = eval.m31_sub(wg_v43, xor_col63);
    let and_tmp_b8fb8_27 = eval.m31_mul(m31_1073741824, wg_v44);
    let wg_v45 = eval.u16_from_m31(op0_limb_6_col7);
    let wg_v46 = eval.u16_from_m31(op1_limb_6_col36);
    let xor_tmp_b8fb8_28 = eval.u16_xor(wg_v45, wg_v46);
    let xor_col64 = eval.u16_as_m31(xor_tmp_b8fb8_28);
    eval.set_col(64, xor_col64);
    eval.set_sub_input_word(28, op0_limb_6_col7);
    eval.set_sub_input_word(29, op1_limb_6_col36);
    eval.set_sub_input_word(30, xor_col64);
    eval.set_lookup_word(90, m31_95781001);
    eval.set_lookup_word(91, op0_limb_6_col7);
    eval.set_lookup_word(92, op1_limb_6_col36);
    eval.set_lookup_word(93, xor_col64);
    let wg_v47 = eval.m31_add(op0_limb_6_col7, op1_limb_6_col36);
    let wg_v48 = eval.m31_sub(wg_v47, xor_col64);
    let and_tmp_b8fb8_30 = eval.m31_mul(m31_1073741824, wg_v48);
    let wg_v49 = eval.u16_from_m31(op0_limb_7_col8);
    let wg_v50 = eval.u16_from_m31(op1_limb_7_col37);
    let xor_tmp_b8fb8_31 = eval.u16_xor(wg_v49, wg_v50);
    let xor_col65 = eval.u16_as_m31(xor_tmp_b8fb8_31);
    eval.set_col(65, xor_col65);
    eval.set_sub_input_word(31, op0_limb_7_col8);
    eval.set_sub_input_word(32, op1_limb_7_col37);
    eval.set_sub_input_word(33, xor_col65);
    eval.set_lookup_word(94, m31_95781001);
    eval.set_lookup_word(95, op0_limb_7_col8);
    eval.set_lookup_word(96, op1_limb_7_col37);
    eval.set_lookup_word(97, xor_col65);
    let wg_v51 = eval.m31_add(op0_limb_7_col8, op1_limb_7_col37);
    let wg_v52 = eval.m31_sub(wg_v51, xor_col65);
    let and_tmp_b8fb8_33 = eval.m31_mul(m31_1073741824, wg_v52);
    let wg_v53 = eval.u16_from_m31(op0_limb_8_col9);
    let wg_v54 = eval.u16_from_m31(op1_limb_8_col38);
    let xor_tmp_b8fb8_34 = eval.u16_xor(wg_v53, wg_v54);
    let xor_col66 = eval.u16_as_m31(xor_tmp_b8fb8_34);
    eval.set_col(66, xor_col66);
    eval.set_sub_input_word(34, op0_limb_8_col9);
    eval.set_sub_input_word(35, op1_limb_8_col38);
    eval.set_sub_input_word(36, xor_col66);
    eval.set_lookup_word(98, m31_95781001);
    eval.set_lookup_word(99, op0_limb_8_col9);
    eval.set_lookup_word(100, op1_limb_8_col38);
    eval.set_lookup_word(101, xor_col66);
    let wg_v55 = eval.m31_add(op0_limb_8_col9, op1_limb_8_col38);
    let wg_v56 = eval.m31_sub(wg_v55, xor_col66);
    let and_tmp_b8fb8_36 = eval.m31_mul(m31_1073741824, wg_v56);
    let wg_v57 = eval.u16_from_m31(op0_limb_9_col10);
    let wg_v58 = eval.u16_from_m31(op1_limb_9_col39);
    let xor_tmp_b8fb8_37 = eval.u16_xor(wg_v57, wg_v58);
    let xor_col67 = eval.u16_as_m31(xor_tmp_b8fb8_37);
    eval.set_col(67, xor_col67);
    eval.set_sub_input_word(37, op0_limb_9_col10);
    eval.set_sub_input_word(38, op1_limb_9_col39);
    eval.set_sub_input_word(39, xor_col67);
    eval.set_lookup_word(102, m31_95781001);
    eval.set_lookup_word(103, op0_limb_9_col10);
    eval.set_lookup_word(104, op1_limb_9_col39);
    eval.set_lookup_word(105, xor_col67);
    let wg_v59 = eval.m31_add(op0_limb_9_col10, op1_limb_9_col39);
    let wg_v60 = eval.m31_sub(wg_v59, xor_col67);
    let and_tmp_b8fb8_39 = eval.m31_mul(m31_1073741824, wg_v60);
    let wg_v61 = eval.u16_from_m31(op0_limb_10_col11);
    let wg_v62 = eval.u16_from_m31(op1_limb_10_col40);
    let xor_tmp_b8fb8_40 = eval.u16_xor(wg_v61, wg_v62);
    let xor_col68 = eval.u16_as_m31(xor_tmp_b8fb8_40);
    eval.set_col(68, xor_col68);
    eval.set_sub_input_word(40, op0_limb_10_col11);
    eval.set_sub_input_word(41, op1_limb_10_col40);
    eval.set_sub_input_word(42, xor_col68);
    eval.set_lookup_word(106, m31_95781001);
    eval.set_lookup_word(107, op0_limb_10_col11);
    eval.set_lookup_word(108, op1_limb_10_col40);
    eval.set_lookup_word(109, xor_col68);
    let wg_v63 = eval.m31_add(op0_limb_10_col11, op1_limb_10_col40);
    let wg_v64 = eval.m31_sub(wg_v63, xor_col68);
    let and_tmp_b8fb8_42 = eval.m31_mul(m31_1073741824, wg_v64);
    let wg_v65 = eval.u16_from_m31(op0_limb_11_col12);
    let wg_v66 = eval.u16_from_m31(op1_limb_11_col41);
    let xor_tmp_b8fb8_43 = eval.u16_xor(wg_v65, wg_v66);
    let xor_col69 = eval.u16_as_m31(xor_tmp_b8fb8_43);
    eval.set_col(69, xor_col69);
    eval.set_sub_input_word(43, op0_limb_11_col12);
    eval.set_sub_input_word(44, op1_limb_11_col41);
    eval.set_sub_input_word(45, xor_col69);
    eval.set_lookup_word(110, m31_95781001);
    eval.set_lookup_word(111, op0_limb_11_col12);
    eval.set_lookup_word(112, op1_limb_11_col41);
    eval.set_lookup_word(113, xor_col69);
    let wg_v67 = eval.m31_add(op0_limb_11_col12, op1_limb_11_col41);
    let wg_v68 = eval.m31_sub(wg_v67, xor_col69);
    let and_tmp_b8fb8_45 = eval.m31_mul(m31_1073741824, wg_v68);
    let wg_v69 = eval.u16_from_m31(op0_limb_12_col13);
    let wg_v70 = eval.u16_from_m31(op1_limb_12_col42);
    let xor_tmp_b8fb8_46 = eval.u16_xor(wg_v69, wg_v70);
    let xor_col70 = eval.u16_as_m31(xor_tmp_b8fb8_46);
    eval.set_col(70, xor_col70);
    eval.set_sub_input_word(46, op0_limb_12_col13);
    eval.set_sub_input_word(47, op1_limb_12_col42);
    eval.set_sub_input_word(48, xor_col70);
    eval.set_lookup_word(114, m31_95781001);
    eval.set_lookup_word(115, op0_limb_12_col13);
    eval.set_lookup_word(116, op1_limb_12_col42);
    eval.set_lookup_word(117, xor_col70);
    let wg_v71 = eval.m31_add(op0_limb_12_col13, op1_limb_12_col42);
    let wg_v72 = eval.m31_sub(wg_v71, xor_col70);
    let and_tmp_b8fb8_48 = eval.m31_mul(m31_1073741824, wg_v72);
    let wg_v73 = eval.u16_from_m31(op0_limb_13_col14);
    let wg_v74 = eval.u16_from_m31(op1_limb_13_col43);
    let xor_tmp_b8fb8_49 = eval.u16_xor(wg_v73, wg_v74);
    let xor_col71 = eval.u16_as_m31(xor_tmp_b8fb8_49);
    eval.set_col(71, xor_col71);
    eval.set_sub_input_word(49, op0_limb_13_col14);
    eval.set_sub_input_word(50, op1_limb_13_col43);
    eval.set_sub_input_word(51, xor_col71);
    eval.set_lookup_word(118, m31_95781001);
    eval.set_lookup_word(119, op0_limb_13_col14);
    eval.set_lookup_word(120, op1_limb_13_col43);
    eval.set_lookup_word(121, xor_col71);
    let wg_v75 = eval.m31_add(op0_limb_13_col14, op1_limb_13_col43);
    let wg_v76 = eval.m31_sub(wg_v75, xor_col71);
    let and_tmp_b8fb8_51 = eval.m31_mul(m31_1073741824, wg_v76);
    let wg_v77 = eval.u16_from_m31(op0_limb_14_col15);
    let wg_v78 = eval.u16_from_m31(op1_limb_14_col44);
    let xor_tmp_b8fb8_52 = eval.u16_xor(wg_v77, wg_v78);
    let xor_col72 = eval.u16_as_m31(xor_tmp_b8fb8_52);
    eval.set_col(72, xor_col72);
    eval.set_sub_input_word(52, op0_limb_14_col15);
    eval.set_sub_input_word(53, op1_limb_14_col44);
    eval.set_sub_input_word(54, xor_col72);
    eval.set_lookup_word(122, m31_95781001);
    eval.set_lookup_word(123, op0_limb_14_col15);
    eval.set_lookup_word(124, op1_limb_14_col44);
    eval.set_lookup_word(125, xor_col72);
    let wg_v79 = eval.m31_add(op0_limb_14_col15, op1_limb_14_col44);
    let wg_v80 = eval.m31_sub(wg_v79, xor_col72);
    let and_tmp_b8fb8_54 = eval.m31_mul(m31_1073741824, wg_v80);
    let wg_v81 = eval.u16_from_m31(op0_limb_15_col16);
    let wg_v82 = eval.u16_from_m31(op1_limb_15_col45);
    let xor_tmp_b8fb8_55 = eval.u16_xor(wg_v81, wg_v82);
    let xor_col73 = eval.u16_as_m31(xor_tmp_b8fb8_55);
    eval.set_col(73, xor_col73);
    eval.set_sub_input_word(55, op0_limb_15_col16);
    eval.set_sub_input_word(56, op1_limb_15_col45);
    eval.set_sub_input_word(57, xor_col73);
    eval.set_lookup_word(126, m31_95781001);
    eval.set_lookup_word(127, op0_limb_15_col16);
    eval.set_lookup_word(128, op1_limb_15_col45);
    eval.set_lookup_word(129, xor_col73);
    let wg_v83 = eval.m31_add(op0_limb_15_col16, op1_limb_15_col45);
    let wg_v84 = eval.m31_sub(wg_v83, xor_col73);
    let and_tmp_b8fb8_57 = eval.m31_mul(m31_1073741824, wg_v84);
    let wg_v85 = eval.u16_from_m31(op0_limb_16_col17);
    let wg_v86 = eval.u16_from_m31(op1_limb_16_col46);
    let xor_tmp_b8fb8_58 = eval.u16_xor(wg_v85, wg_v86);
    let xor_col74 = eval.u16_as_m31(xor_tmp_b8fb8_58);
    eval.set_col(74, xor_col74);
    eval.set_sub_input_word(58, op0_limb_16_col17);
    eval.set_sub_input_word(59, op1_limb_16_col46);
    eval.set_sub_input_word(60, xor_col74);
    eval.set_lookup_word(130, m31_95781001);
    eval.set_lookup_word(131, op0_limb_16_col17);
    eval.set_lookup_word(132, op1_limb_16_col46);
    eval.set_lookup_word(133, xor_col74);
    let wg_v87 = eval.m31_add(op0_limb_16_col17, op1_limb_16_col46);
    let wg_v88 = eval.m31_sub(wg_v87, xor_col74);
    let and_tmp_b8fb8_60 = eval.m31_mul(m31_1073741824, wg_v88);
    let wg_v89 = eval.u16_from_m31(op0_limb_17_col18);
    let wg_v90 = eval.u16_from_m31(op1_limb_17_col47);
    let xor_tmp_b8fb8_61 = eval.u16_xor(wg_v89, wg_v90);
    let xor_col75 = eval.u16_as_m31(xor_tmp_b8fb8_61);
    eval.set_col(75, xor_col75);
    eval.set_sub_input_word(61, op0_limb_17_col18);
    eval.set_sub_input_word(62, op1_limb_17_col47);
    eval.set_sub_input_word(63, xor_col75);
    eval.set_lookup_word(134, m31_95781001);
    eval.set_lookup_word(135, op0_limb_17_col18);
    eval.set_lookup_word(136, op1_limb_17_col47);
    eval.set_lookup_word(137, xor_col75);
    let wg_v91 = eval.m31_add(op0_limb_17_col18, op1_limb_17_col47);
    let wg_v92 = eval.m31_sub(wg_v91, xor_col75);
    let and_tmp_b8fb8_63 = eval.m31_mul(m31_1073741824, wg_v92);
    let wg_v93 = eval.u16_from_m31(op0_limb_18_col19);
    let wg_v94 = eval.u16_from_m31(op1_limb_18_col48);
    let xor_tmp_b8fb8_64 = eval.u16_xor(wg_v93, wg_v94);
    let xor_col76 = eval.u16_as_m31(xor_tmp_b8fb8_64);
    eval.set_col(76, xor_col76);
    eval.set_sub_input_word(64, op0_limb_18_col19);
    eval.set_sub_input_word(65, op1_limb_18_col48);
    eval.set_sub_input_word(66, xor_col76);
    eval.set_lookup_word(138, m31_95781001);
    eval.set_lookup_word(139, op0_limb_18_col19);
    eval.set_lookup_word(140, op1_limb_18_col48);
    eval.set_lookup_word(141, xor_col76);
    let wg_v95 = eval.m31_add(op0_limb_18_col19, op1_limb_18_col48);
    let wg_v96 = eval.m31_sub(wg_v95, xor_col76);
    let and_tmp_b8fb8_66 = eval.m31_mul(m31_1073741824, wg_v96);
    let wg_v97 = eval.u16_from_m31(op0_limb_19_col20);
    let wg_v98 = eval.u16_from_m31(op1_limb_19_col49);
    let xor_tmp_b8fb8_67 = eval.u16_xor(wg_v97, wg_v98);
    let xor_col77 = eval.u16_as_m31(xor_tmp_b8fb8_67);
    eval.set_col(77, xor_col77);
    eval.set_sub_input_word(67, op0_limb_19_col20);
    eval.set_sub_input_word(68, op1_limb_19_col49);
    eval.set_sub_input_word(69, xor_col77);
    eval.set_lookup_word(142, m31_95781001);
    eval.set_lookup_word(143, op0_limb_19_col20);
    eval.set_lookup_word(144, op1_limb_19_col49);
    eval.set_lookup_word(145, xor_col77);
    let wg_v99 = eval.m31_add(op0_limb_19_col20, op1_limb_19_col49);
    let wg_v100 = eval.m31_sub(wg_v99, xor_col77);
    let and_tmp_b8fb8_69 = eval.m31_mul(m31_1073741824, wg_v100);
    let wg_v101 = eval.u16_from_m31(op0_limb_20_col21);
    let wg_v102 = eval.u16_from_m31(op1_limb_20_col50);
    let xor_tmp_b8fb8_70 = eval.u16_xor(wg_v101, wg_v102);
    let xor_col78 = eval.u16_as_m31(xor_tmp_b8fb8_70);
    eval.set_col(78, xor_col78);
    eval.set_sub_input_word(70, op0_limb_20_col21);
    eval.set_sub_input_word(71, op1_limb_20_col50);
    eval.set_sub_input_word(72, xor_col78);
    eval.set_lookup_word(146, m31_95781001);
    eval.set_lookup_word(147, op0_limb_20_col21);
    eval.set_lookup_word(148, op1_limb_20_col50);
    eval.set_lookup_word(149, xor_col78);
    let wg_v103 = eval.m31_add(op0_limb_20_col21, op1_limb_20_col50);
    let wg_v104 = eval.m31_sub(wg_v103, xor_col78);
    let and_tmp_b8fb8_72 = eval.m31_mul(m31_1073741824, wg_v104);
    let wg_v105 = eval.u16_from_m31(op0_limb_21_col22);
    let wg_v106 = eval.u16_from_m31(op1_limb_21_col51);
    let xor_tmp_b8fb8_73 = eval.u16_xor(wg_v105, wg_v106);
    let xor_col79 = eval.u16_as_m31(xor_tmp_b8fb8_73);
    eval.set_col(79, xor_col79);
    eval.set_sub_input_word(73, op0_limb_21_col22);
    eval.set_sub_input_word(74, op1_limb_21_col51);
    eval.set_sub_input_word(75, xor_col79);
    eval.set_lookup_word(150, m31_95781001);
    eval.set_lookup_word(151, op0_limb_21_col22);
    eval.set_lookup_word(152, op1_limb_21_col51);
    eval.set_lookup_word(153, xor_col79);
    let wg_v107 = eval.m31_add(op0_limb_21_col22, op1_limb_21_col51);
    let wg_v108 = eval.m31_sub(wg_v107, xor_col79);
    let and_tmp_b8fb8_75 = eval.m31_mul(m31_1073741824, wg_v108);
    let wg_v109 = eval.u16_from_m31(op0_limb_22_col23);
    let wg_v110 = eval.u16_from_m31(op1_limb_22_col52);
    let xor_tmp_b8fb8_76 = eval.u16_xor(wg_v109, wg_v110);
    let xor_col80 = eval.u16_as_m31(xor_tmp_b8fb8_76);
    eval.set_col(80, xor_col80);
    eval.set_sub_input_word(76, op0_limb_22_col23);
    eval.set_sub_input_word(77, op1_limb_22_col52);
    eval.set_sub_input_word(78, xor_col80);
    eval.set_lookup_word(154, m31_95781001);
    eval.set_lookup_word(155, op0_limb_22_col23);
    eval.set_lookup_word(156, op1_limb_22_col52);
    eval.set_lookup_word(157, xor_col80);
    let wg_v111 = eval.m31_add(op0_limb_22_col23, op1_limb_22_col52);
    let wg_v112 = eval.m31_sub(wg_v111, xor_col80);
    let and_tmp_b8fb8_78 = eval.m31_mul(m31_1073741824, wg_v112);
    let wg_v113 = eval.u16_from_m31(op0_limb_23_col24);
    let wg_v114 = eval.u16_from_m31(op1_limb_23_col53);
    let xor_tmp_b8fb8_79 = eval.u16_xor(wg_v113, wg_v114);
    let xor_col81 = eval.u16_as_m31(xor_tmp_b8fb8_79);
    eval.set_col(81, xor_col81);
    eval.set_sub_input_word(79, op0_limb_23_col24);
    eval.set_sub_input_word(80, op1_limb_23_col53);
    eval.set_sub_input_word(81, xor_col81);
    eval.set_lookup_word(158, m31_95781001);
    eval.set_lookup_word(159, op0_limb_23_col24);
    eval.set_lookup_word(160, op1_limb_23_col53);
    eval.set_lookup_word(161, xor_col81);
    let wg_v115 = eval.m31_add(op0_limb_23_col24, op1_limb_23_col53);
    let wg_v116 = eval.m31_sub(wg_v115, xor_col81);
    let and_tmp_b8fb8_81 = eval.m31_mul(m31_1073741824, wg_v116);
    let wg_v117 = eval.u16_from_m31(op0_limb_24_col25);
    let wg_v118 = eval.u16_from_m31(op1_limb_24_col54);
    let xor_tmp_b8fb8_82 = eval.u16_xor(wg_v117, wg_v118);
    let xor_col82 = eval.u16_as_m31(xor_tmp_b8fb8_82);
    eval.set_col(82, xor_col82);
    eval.set_sub_input_word(82, op0_limb_24_col25);
    eval.set_sub_input_word(83, op1_limb_24_col54);
    eval.set_sub_input_word(84, xor_col82);
    eval.set_lookup_word(162, m31_95781001);
    eval.set_lookup_word(163, op0_limb_24_col25);
    eval.set_lookup_word(164, op1_limb_24_col54);
    eval.set_lookup_word(165, xor_col82);
    let wg_v119 = eval.m31_add(op0_limb_24_col25, op1_limb_24_col54);
    let wg_v120 = eval.m31_sub(wg_v119, xor_col82);
    let and_tmp_b8fb8_84 = eval.m31_mul(m31_1073741824, wg_v120);
    let wg_v121 = eval.u16_from_m31(op0_limb_25_col26);
    let wg_v122 = eval.u16_from_m31(op1_limb_25_col55);
    let xor_tmp_b8fb8_85 = eval.u16_xor(wg_v121, wg_v122);
    let xor_col83 = eval.u16_as_m31(xor_tmp_b8fb8_85);
    eval.set_col(83, xor_col83);
    eval.set_sub_input_word(85, op0_limb_25_col26);
    eval.set_sub_input_word(86, op1_limb_25_col55);
    eval.set_sub_input_word(87, xor_col83);
    eval.set_lookup_word(166, m31_95781001);
    eval.set_lookup_word(167, op0_limb_25_col26);
    eval.set_lookup_word(168, op1_limb_25_col55);
    eval.set_lookup_word(169, xor_col83);
    let wg_v123 = eval.m31_add(op0_limb_25_col26, op1_limb_25_col55);
    let wg_v124 = eval.m31_sub(wg_v123, xor_col83);
    let and_tmp_b8fb8_87 = eval.m31_mul(m31_1073741824, wg_v124);
    let wg_v125 = eval.u16_from_m31(op0_limb_26_col27);
    let wg_v126 = eval.u16_from_m31(op1_limb_26_col56);
    let xor_tmp_b8fb8_88 = eval.u16_xor(wg_v125, wg_v126);
    let xor_col84 = eval.u16_as_m31(xor_tmp_b8fb8_88);
    eval.set_col(84, xor_col84);
    eval.set_sub_input_word(88, op0_limb_26_col27);
    eval.set_sub_input_word(89, op1_limb_26_col56);
    eval.set_sub_input_word(90, xor_col84);
    eval.set_lookup_word(170, m31_95781001);
    eval.set_lookup_word(171, op0_limb_26_col27);
    eval.set_lookup_word(172, op1_limb_26_col56);
    eval.set_lookup_word(173, xor_col84);
    let wg_v127 = eval.m31_add(op0_limb_26_col27, op1_limb_26_col56);
    let wg_v128 = eval.m31_sub(wg_v127, xor_col84);
    let and_tmp_b8fb8_90 = eval.m31_mul(m31_1073741824, wg_v128);
    let wg_v129 = eval.u16_from_m31(op0_limb_27_col28);
    let wg_v130 = eval.u16_from_m31(op1_limb_27_col57);
    let xor_tmp_b8fb8_91 = eval.u16_xor(wg_v129, wg_v130);
    let xor_col85 = eval.u16_as_m31(xor_tmp_b8fb8_91);
    eval.set_col(85, xor_col85);
    eval.set_sub_input_word(91, op0_limb_27_col28);
    eval.set_sub_input_word(92, op1_limb_27_col57);
    eval.set_sub_input_word(93, xor_col85);
    eval.set_lookup_word(174, m31_112558620);
    eval.set_lookup_word(175, op0_limb_27_col28);
    eval.set_lookup_word(176, op1_limb_27_col57);
    eval.set_lookup_word(177, xor_col85);
    let wg_v131 = eval.m31_add(op0_limb_27_col28, op1_limb_27_col57);
    let wg_v132 = eval.m31_sub(wg_v131, xor_col85);
    let and_tmp_b8fb8_93 = eval.m31_mul(m31_1073741824, wg_v132);
    let wg_v133 = eval.input(0);
    let wg_v134 = eval.m31_mul(seq, m31_5);
    let wg_v135 = eval.m31_add(wg_v133, wg_v134);
    let wg_v136 = eval.m31_add(wg_v135, m31_2);
    let memory_address_to_id_value_tmp_b8fb8_94 = eval.mem_addr_to_id(wg_v136);
    let and_id_col86 = memory_address_to_id_value_tmp_b8fb8_94;
    eval.set_col(86, and_id_col86);
    let wg_v137 = eval.input(0);
    let wg_v138 = eval.m31_mul(seq, m31_5);
    let wg_v139 = eval.m31_add(wg_v137, wg_v138);
    let wg_v140 = eval.m31_add(wg_v139, m31_2);
    eval.set_sub_input_word(2, wg_v140);
    eval.set_lookup_word(178, m31_1444891767);
    let wg_v141 = eval.input(0);
    let wg_v142 = eval.m31_mul(seq, m31_5);
    let wg_v143 = eval.m31_add(wg_v141, wg_v142);
    let wg_v144 = eval.m31_add(wg_v143, m31_2);
    eval.set_lookup_word(179, wg_v144);
    eval.set_lookup_word(180, and_id_col86);
    eval.set_sub_input_word(7, and_id_col86);
    eval.set_lookup_word(181, m31_1662111297);
    eval.set_lookup_word(182, and_id_col86);
    eval.set_lookup_word(183, and_tmp_b8fb8_12);
    eval.set_lookup_word(184, and_tmp_b8fb8_15);
    eval.set_lookup_word(185, and_tmp_b8fb8_18);
    eval.set_lookup_word(186, and_tmp_b8fb8_21);
    eval.set_lookup_word(187, and_tmp_b8fb8_24);
    eval.set_lookup_word(188, and_tmp_b8fb8_27);
    eval.set_lookup_word(189, and_tmp_b8fb8_30);
    eval.set_lookup_word(190, and_tmp_b8fb8_33);
    eval.set_lookup_word(191, and_tmp_b8fb8_36);
    eval.set_lookup_word(192, and_tmp_b8fb8_39);
    eval.set_lookup_word(193, and_tmp_b8fb8_42);
    eval.set_lookup_word(194, and_tmp_b8fb8_45);
    eval.set_lookup_word(195, and_tmp_b8fb8_48);
    eval.set_lookup_word(196, and_tmp_b8fb8_51);
    eval.set_lookup_word(197, and_tmp_b8fb8_54);
    eval.set_lookup_word(198, and_tmp_b8fb8_57);
    eval.set_lookup_word(199, and_tmp_b8fb8_60);
    eval.set_lookup_word(200, and_tmp_b8fb8_63);
    eval.set_lookup_word(201, and_tmp_b8fb8_66);
    eval.set_lookup_word(202, and_tmp_b8fb8_69);
    eval.set_lookup_word(203, and_tmp_b8fb8_72);
    eval.set_lookup_word(204, and_tmp_b8fb8_75);
    eval.set_lookup_word(205, and_tmp_b8fb8_78);
    eval.set_lookup_word(206, and_tmp_b8fb8_81);
    eval.set_lookup_word(207, and_tmp_b8fb8_84);
    eval.set_lookup_word(208, and_tmp_b8fb8_87);
    eval.set_lookup_word(209, and_tmp_b8fb8_90);
    eval.set_lookup_word(210, and_tmp_b8fb8_93);
    let wg_v145 = eval.input(0);
    let wg_v146 = eval.m31_mul(seq, m31_5);
    let wg_v147 = eval.m31_add(wg_v145, wg_v146);
    let wg_v148 = eval.m31_add(wg_v147, m31_3);
    let memory_address_to_id_value_tmp_b8fb8_96 = eval.mem_addr_to_id(wg_v148);
    let xor_id_col87 = memory_address_to_id_value_tmp_b8fb8_96;
    eval.set_col(87, xor_id_col87);
    let wg_v149 = eval.input(0);
    let wg_v150 = eval.m31_mul(seq, m31_5);
    let wg_v151 = eval.m31_add(wg_v149, wg_v150);
    let wg_v152 = eval.m31_add(wg_v151, m31_3);
    eval.set_sub_input_word(3, wg_v152);
    eval.set_lookup_word(211, m31_1444891767);
    let wg_v153 = eval.input(0);
    let wg_v154 = eval.m31_mul(seq, m31_5);
    let wg_v155 = eval.m31_add(wg_v153, wg_v154);
    let wg_v156 = eval.m31_add(wg_v155, m31_3);
    eval.set_lookup_word(212, wg_v156);
    eval.set_lookup_word(213, xor_id_col87);
    eval.set_sub_input_word(8, xor_id_col87);
    eval.set_lookup_word(214, m31_1662111297);
    eval.set_lookup_word(215, xor_id_col87);
    eval.set_lookup_word(216, xor_col58);
    eval.set_lookup_word(217, xor_col59);
    eval.set_lookup_word(218, xor_col60);
    eval.set_lookup_word(219, xor_col61);
    eval.set_lookup_word(220, xor_col62);
    eval.set_lookup_word(221, xor_col63);
    eval.set_lookup_word(222, xor_col64);
    eval.set_lookup_word(223, xor_col65);
    eval.set_lookup_word(224, xor_col66);
    eval.set_lookup_word(225, xor_col67);
    eval.set_lookup_word(226, xor_col68);
    eval.set_lookup_word(227, xor_col69);
    eval.set_lookup_word(228, xor_col70);
    eval.set_lookup_word(229, xor_col71);
    eval.set_lookup_word(230, xor_col72);
    eval.set_lookup_word(231, xor_col73);
    eval.set_lookup_word(232, xor_col74);
    eval.set_lookup_word(233, xor_col75);
    eval.set_lookup_word(234, xor_col76);
    eval.set_lookup_word(235, xor_col77);
    eval.set_lookup_word(236, xor_col78);
    eval.set_lookup_word(237, xor_col79);
    eval.set_lookup_word(238, xor_col80);
    eval.set_lookup_word(239, xor_col81);
    eval.set_lookup_word(240, xor_col82);
    eval.set_lookup_word(241, xor_col83);
    eval.set_lookup_word(242, xor_col84);
    eval.set_lookup_word(243, xor_col85);
    let wg_v157 = eval.input(0);
    let wg_v158 = eval.m31_mul(seq, m31_5);
    let wg_v159 = eval.m31_add(wg_v157, wg_v158);
    let wg_v160 = eval.m31_add(wg_v159, m31_4);
    let memory_address_to_id_value_tmp_b8fb8_98 = eval.mem_addr_to_id(wg_v160);
    let or_id_col88 = memory_address_to_id_value_tmp_b8fb8_98;
    eval.set_col(88, or_id_col88);
    let wg_v161 = eval.input(0);
    let wg_v162 = eval.m31_mul(seq, m31_5);
    let wg_v163 = eval.m31_add(wg_v161, wg_v162);
    let wg_v164 = eval.m31_add(wg_v163, m31_4);
    eval.set_sub_input_word(4, wg_v164);
    eval.set_lookup_word(244, m31_1444891767);
    let wg_v165 = eval.input(0);
    let wg_v166 = eval.m31_mul(seq, m31_5);
    let wg_v167 = eval.m31_add(wg_v165, wg_v166);
    let wg_v168 = eval.m31_add(wg_v167, m31_4);
    eval.set_lookup_word(245, wg_v168);
    eval.set_lookup_word(246, or_id_col88);
    eval.set_sub_input_word(9, or_id_col88);
    eval.set_lookup_word(247, m31_1662111297);
    eval.set_lookup_word(248, or_id_col88);
    let wg_v169 = eval.m31_add(and_tmp_b8fb8_12, xor_col58);
    eval.set_lookup_word(249, wg_v169);
    let wg_v170 = eval.m31_add(and_tmp_b8fb8_15, xor_col59);
    eval.set_lookup_word(250, wg_v170);
    let wg_v171 = eval.m31_add(and_tmp_b8fb8_18, xor_col60);
    eval.set_lookup_word(251, wg_v171);
    let wg_v172 = eval.m31_add(and_tmp_b8fb8_21, xor_col61);
    eval.set_lookup_word(252, wg_v172);
    let wg_v173 = eval.m31_add(and_tmp_b8fb8_24, xor_col62);
    eval.set_lookup_word(253, wg_v173);
    let wg_v174 = eval.m31_add(and_tmp_b8fb8_27, xor_col63);
    eval.set_lookup_word(254, wg_v174);
    let wg_v175 = eval.m31_add(and_tmp_b8fb8_30, xor_col64);
    eval.set_lookup_word(255, wg_v175);
    let wg_v176 = eval.m31_add(and_tmp_b8fb8_33, xor_col65);
    eval.set_lookup_word(256, wg_v176);
    let wg_v177 = eval.m31_add(and_tmp_b8fb8_36, xor_col66);
    eval.set_lookup_word(257, wg_v177);
    let wg_v178 = eval.m31_add(and_tmp_b8fb8_39, xor_col67);
    eval.set_lookup_word(258, wg_v178);
    let wg_v179 = eval.m31_add(and_tmp_b8fb8_42, xor_col68);
    eval.set_lookup_word(259, wg_v179);
    let wg_v180 = eval.m31_add(and_tmp_b8fb8_45, xor_col69);
    eval.set_lookup_word(260, wg_v180);
    let wg_v181 = eval.m31_add(and_tmp_b8fb8_48, xor_col70);
    eval.set_lookup_word(261, wg_v181);
    let wg_v182 = eval.m31_add(and_tmp_b8fb8_51, xor_col71);
    eval.set_lookup_word(262, wg_v182);
    let wg_v183 = eval.m31_add(and_tmp_b8fb8_54, xor_col72);
    eval.set_lookup_word(263, wg_v183);
    let wg_v184 = eval.m31_add(and_tmp_b8fb8_57, xor_col73);
    eval.set_lookup_word(264, wg_v184);
    let wg_v185 = eval.m31_add(and_tmp_b8fb8_60, xor_col74);
    eval.set_lookup_word(265, wg_v185);
    let wg_v186 = eval.m31_add(and_tmp_b8fb8_63, xor_col75);
    eval.set_lookup_word(266, wg_v186);
    let wg_v187 = eval.m31_add(and_tmp_b8fb8_66, xor_col76);
    eval.set_lookup_word(267, wg_v187);
    let wg_v188 = eval.m31_add(and_tmp_b8fb8_69, xor_col77);
    eval.set_lookup_word(268, wg_v188);
    let wg_v189 = eval.m31_add(and_tmp_b8fb8_72, xor_col78);
    eval.set_lookup_word(269, wg_v189);
    let wg_v190 = eval.m31_add(and_tmp_b8fb8_75, xor_col79);
    eval.set_lookup_word(270, wg_v190);
    let wg_v191 = eval.m31_add(and_tmp_b8fb8_78, xor_col80);
    eval.set_lookup_word(271, wg_v191);
    let wg_v192 = eval.m31_add(and_tmp_b8fb8_81, xor_col81);
    eval.set_lookup_word(272, wg_v192);
    let wg_v193 = eval.m31_add(and_tmp_b8fb8_84, xor_col82);
    eval.set_lookup_word(273, wg_v193);
    let wg_v194 = eval.m31_add(and_tmp_b8fb8_87, xor_col83);
    eval.set_lookup_word(274, wg_v194);
    let wg_v195 = eval.m31_add(and_tmp_b8fb8_90, xor_col84);
    eval.set_lookup_word(275, wg_v195);
    let wg_v196 = eval.m31_add(and_tmp_b8fb8_93, xor_col85);
    eval.set_lookup_word(276, wg_v196);
    eval.set_lookup_word(277, m31_1);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `bitwise_builtin_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    log_size: u32,
    bitwise_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_bitwise_xor_9_state: &verify_bitwise_xor_9::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
) -> (
    ComponentTrace<N_TRACE_COLUMNS>,
    LookupData,
    SubComponentInputs,
) {
    let log_n_packed_rows = log_size - LOG_N_LANES;
    let (mut trace, mut lookup_data, mut sub_component_inputs) = unsafe {
        (
            ComponentTrace::<N_TRACE_COLUMNS>::uninitialized(log_size),
            LookupData::uninitialized(log_n_packed_rows),
            SubComponentInputs::uninitialized(log_n_packed_rows),
        )
    };
    let seq = Seq::new(log_size);
    let enabler_col = Enabler::new(0);
    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(|(row_index, (row, lookup_data, sub_component_inputs))| {
            let mut eval = SimdWitnessEval::new(
                row,
                memory_address_to_id_state,
                memory_id_to_big_state,
                vec![Simd::splat(bitwise_builtin_segment_start)],
                row_index,
                &enabler_col,
                N_LOOKUP_WORDS,
                N_SUB_INPUT_WORDS,
            );
            bitwise_builtin_row_body(&mut eval);
            let lw = eval.lookup_scratch();
            *lookup_data.memory_address_to_id_0 = [lw[0], lw[1], lw[2]];
            *lookup_data.memory_id_to_big_1 = [
                lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10], lw[11], lw[12], lw[13],
                lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20], lw[21], lw[22], lw[23],
                lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30], lw[31], lw[32],
            ];
            *lookup_data.memory_address_to_id_2 = [lw[33], lw[34], lw[35]];
            *lookup_data.memory_id_to_big_3 = [
                lw[36], lw[37], lw[38], lw[39], lw[40], lw[41], lw[42], lw[43], lw[44], lw[45],
                lw[46], lw[47], lw[48], lw[49], lw[50], lw[51], lw[52], lw[53], lw[54], lw[55],
                lw[56], lw[57], lw[58], lw[59], lw[60], lw[61], lw[62], lw[63], lw[64], lw[65],
            ];
            *lookup_data.verify_bitwise_xor_9_4 = [lw[66], lw[67], lw[68], lw[69]];
            *lookup_data.verify_bitwise_xor_9_5 = [lw[70], lw[71], lw[72], lw[73]];
            *lookup_data.verify_bitwise_xor_9_6 = [lw[74], lw[75], lw[76], lw[77]];
            *lookup_data.verify_bitwise_xor_9_7 = [lw[78], lw[79], lw[80], lw[81]];
            *lookup_data.verify_bitwise_xor_9_8 = [lw[82], lw[83], lw[84], lw[85]];
            *lookup_data.verify_bitwise_xor_9_9 = [lw[86], lw[87], lw[88], lw[89]];
            *lookup_data.verify_bitwise_xor_9_10 = [lw[90], lw[91], lw[92], lw[93]];
            *lookup_data.verify_bitwise_xor_9_11 = [lw[94], lw[95], lw[96], lw[97]];
            *lookup_data.verify_bitwise_xor_9_12 = [lw[98], lw[99], lw[100], lw[101]];
            *lookup_data.verify_bitwise_xor_9_13 = [lw[102], lw[103], lw[104], lw[105]];
            *lookup_data.verify_bitwise_xor_9_14 = [lw[106], lw[107], lw[108], lw[109]];
            *lookup_data.verify_bitwise_xor_9_15 = [lw[110], lw[111], lw[112], lw[113]];
            *lookup_data.verify_bitwise_xor_9_16 = [lw[114], lw[115], lw[116], lw[117]];
            *lookup_data.verify_bitwise_xor_9_17 = [lw[118], lw[119], lw[120], lw[121]];
            *lookup_data.verify_bitwise_xor_9_18 = [lw[122], lw[123], lw[124], lw[125]];
            *lookup_data.verify_bitwise_xor_9_19 = [lw[126], lw[127], lw[128], lw[129]];
            *lookup_data.verify_bitwise_xor_9_20 = [lw[130], lw[131], lw[132], lw[133]];
            *lookup_data.verify_bitwise_xor_9_21 = [lw[134], lw[135], lw[136], lw[137]];
            *lookup_data.verify_bitwise_xor_9_22 = [lw[138], lw[139], lw[140], lw[141]];
            *lookup_data.verify_bitwise_xor_9_23 = [lw[142], lw[143], lw[144], lw[145]];
            *lookup_data.verify_bitwise_xor_9_24 = [lw[146], lw[147], lw[148], lw[149]];
            *lookup_data.verify_bitwise_xor_9_25 = [lw[150], lw[151], lw[152], lw[153]];
            *lookup_data.verify_bitwise_xor_9_26 = [lw[154], lw[155], lw[156], lw[157]];
            *lookup_data.verify_bitwise_xor_9_27 = [lw[158], lw[159], lw[160], lw[161]];
            *lookup_data.verify_bitwise_xor_9_28 = [lw[162], lw[163], lw[164], lw[165]];
            *lookup_data.verify_bitwise_xor_9_29 = [lw[166], lw[167], lw[168], lw[169]];
            *lookup_data.verify_bitwise_xor_9_30 = [lw[170], lw[171], lw[172], lw[173]];
            *lookup_data.verify_bitwise_xor_8_31 = [lw[174], lw[175], lw[176], lw[177]];
            *lookup_data.memory_address_to_id_32 = [lw[178], lw[179], lw[180]];
            *lookup_data.memory_id_to_big_33 = [
                lw[181], lw[182], lw[183], lw[184], lw[185], lw[186], lw[187], lw[188], lw[189],
                lw[190], lw[191], lw[192], lw[193], lw[194], lw[195], lw[196], lw[197], lw[198],
                lw[199], lw[200], lw[201], lw[202], lw[203], lw[204], lw[205], lw[206], lw[207],
                lw[208], lw[209], lw[210],
            ];
            *lookup_data.memory_address_to_id_34 = [lw[211], lw[212], lw[213]];
            *lookup_data.memory_id_to_big_35 = [
                lw[214], lw[215], lw[216], lw[217], lw[218], lw[219], lw[220], lw[221], lw[222],
                lw[223], lw[224], lw[225], lw[226], lw[227], lw[228], lw[229], lw[230], lw[231],
                lw[232], lw[233], lw[234], lw[235], lw[236], lw[237], lw[238], lw[239], lw[240],
                lw[241], lw[242], lw[243],
            ];
            *lookup_data.memory_address_to_id_36 = [lw[244], lw[245], lw[246]];
            *lookup_data.memory_id_to_big_37 = [
                lw[247], lw[248], lw[249], lw[250], lw[251], lw[252], lw[253], lw[254], lw[255],
                lw[256], lw[257], lw[258], lw[259], lw[260], lw[261], lw[262], lw[263], lw[264],
                lw[265], lw[266], lw[267], lw[268], lw[269], lw[270], lw[271], lw[272], lw[273],
                lw[274], lw[275], lw[276],
            ];
            *lookup_data.mults_0 = lw[277];
            let sw = eval.sub_scratch();
            *sub_component_inputs.memory_address_to_id[0] =
                unsafe { PackedM31::from_simd_unchecked(sw[0]) };
            *sub_component_inputs.memory_address_to_id[1] =
                unsafe { PackedM31::from_simd_unchecked(sw[1]) };
            *sub_component_inputs.memory_address_to_id[2] =
                unsafe { PackedM31::from_simd_unchecked(sw[2]) };
            *sub_component_inputs.memory_address_to_id[3] =
                unsafe { PackedM31::from_simd_unchecked(sw[3]) };
            *sub_component_inputs.memory_address_to_id[4] =
                unsafe { PackedM31::from_simd_unchecked(sw[4]) };
            *sub_component_inputs.memory_id_to_big[0] =
                unsafe { PackedM31::from_simd_unchecked(sw[5]) };
            *sub_component_inputs.memory_id_to_big[1] =
                unsafe { PackedM31::from_simd_unchecked(sw[6]) };
            *sub_component_inputs.memory_id_to_big[2] =
                unsafe { PackedM31::from_simd_unchecked(sw[7]) };
            *sub_component_inputs.memory_id_to_big[3] =
                unsafe { PackedM31::from_simd_unchecked(sw[8]) };
            *sub_component_inputs.memory_id_to_big[4] =
                unsafe { PackedM31::from_simd_unchecked(sw[9]) };
            *sub_component_inputs.verify_bitwise_xor_9[0] = [
                unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                unsafe { PackedM31::from_simd_unchecked(sw[12]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[1] = [
                unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                unsafe { PackedM31::from_simd_unchecked(sw[15]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[2] = [
                unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                unsafe { PackedM31::from_simd_unchecked(sw[18]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[3] = [
                unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                unsafe { PackedM31::from_simd_unchecked(sw[21]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[4] = [
                unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                unsafe { PackedM31::from_simd_unchecked(sw[23]) },
                unsafe { PackedM31::from_simd_unchecked(sw[24]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[5] = [
                unsafe { PackedM31::from_simd_unchecked(sw[25]) },
                unsafe { PackedM31::from_simd_unchecked(sw[26]) },
                unsafe { PackedM31::from_simd_unchecked(sw[27]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[6] = [
                unsafe { PackedM31::from_simd_unchecked(sw[28]) },
                unsafe { PackedM31::from_simd_unchecked(sw[29]) },
                unsafe { PackedM31::from_simd_unchecked(sw[30]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[7] = [
                unsafe { PackedM31::from_simd_unchecked(sw[31]) },
                unsafe { PackedM31::from_simd_unchecked(sw[32]) },
                unsafe { PackedM31::from_simd_unchecked(sw[33]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[8] = [
                unsafe { PackedM31::from_simd_unchecked(sw[34]) },
                unsafe { PackedM31::from_simd_unchecked(sw[35]) },
                unsafe { PackedM31::from_simd_unchecked(sw[36]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[9] = [
                unsafe { PackedM31::from_simd_unchecked(sw[37]) },
                unsafe { PackedM31::from_simd_unchecked(sw[38]) },
                unsafe { PackedM31::from_simd_unchecked(sw[39]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[10] = [
                unsafe { PackedM31::from_simd_unchecked(sw[40]) },
                unsafe { PackedM31::from_simd_unchecked(sw[41]) },
                unsafe { PackedM31::from_simd_unchecked(sw[42]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[11] = [
                unsafe { PackedM31::from_simd_unchecked(sw[43]) },
                unsafe { PackedM31::from_simd_unchecked(sw[44]) },
                unsafe { PackedM31::from_simd_unchecked(sw[45]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[12] = [
                unsafe { PackedM31::from_simd_unchecked(sw[46]) },
                unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                unsafe { PackedM31::from_simd_unchecked(sw[48]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[13] = [
                unsafe { PackedM31::from_simd_unchecked(sw[49]) },
                unsafe { PackedM31::from_simd_unchecked(sw[50]) },
                unsafe { PackedM31::from_simd_unchecked(sw[51]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[14] = [
                unsafe { PackedM31::from_simd_unchecked(sw[52]) },
                unsafe { PackedM31::from_simd_unchecked(sw[53]) },
                unsafe { PackedM31::from_simd_unchecked(sw[54]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[15] = [
                unsafe { PackedM31::from_simd_unchecked(sw[55]) },
                unsafe { PackedM31::from_simd_unchecked(sw[56]) },
                unsafe { PackedM31::from_simd_unchecked(sw[57]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[16] = [
                unsafe { PackedM31::from_simd_unchecked(sw[58]) },
                unsafe { PackedM31::from_simd_unchecked(sw[59]) },
                unsafe { PackedM31::from_simd_unchecked(sw[60]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[17] = [
                unsafe { PackedM31::from_simd_unchecked(sw[61]) },
                unsafe { PackedM31::from_simd_unchecked(sw[62]) },
                unsafe { PackedM31::from_simd_unchecked(sw[63]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[18] = [
                unsafe { PackedM31::from_simd_unchecked(sw[64]) },
                unsafe { PackedM31::from_simd_unchecked(sw[65]) },
                unsafe { PackedM31::from_simd_unchecked(sw[66]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[19] = [
                unsafe { PackedM31::from_simd_unchecked(sw[67]) },
                unsafe { PackedM31::from_simd_unchecked(sw[68]) },
                unsafe { PackedM31::from_simd_unchecked(sw[69]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[20] = [
                unsafe { PackedM31::from_simd_unchecked(sw[70]) },
                unsafe { PackedM31::from_simd_unchecked(sw[71]) },
                unsafe { PackedM31::from_simd_unchecked(sw[72]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[21] = [
                unsafe { PackedM31::from_simd_unchecked(sw[73]) },
                unsafe { PackedM31::from_simd_unchecked(sw[74]) },
                unsafe { PackedM31::from_simd_unchecked(sw[75]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[22] = [
                unsafe { PackedM31::from_simd_unchecked(sw[76]) },
                unsafe { PackedM31::from_simd_unchecked(sw[77]) },
                unsafe { PackedM31::from_simd_unchecked(sw[78]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[23] = [
                unsafe { PackedM31::from_simd_unchecked(sw[79]) },
                unsafe { PackedM31::from_simd_unchecked(sw[80]) },
                unsafe { PackedM31::from_simd_unchecked(sw[81]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[24] = [
                unsafe { PackedM31::from_simd_unchecked(sw[82]) },
                unsafe { PackedM31::from_simd_unchecked(sw[83]) },
                unsafe { PackedM31::from_simd_unchecked(sw[84]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[25] = [
                unsafe { PackedM31::from_simd_unchecked(sw[85]) },
                unsafe { PackedM31::from_simd_unchecked(sw[86]) },
                unsafe { PackedM31::from_simd_unchecked(sw[87]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_9[26] = [
                unsafe { PackedM31::from_simd_unchecked(sw[88]) },
                unsafe { PackedM31::from_simd_unchecked(sw[89]) },
                unsafe { PackedM31::from_simd_unchecked(sw[90]) },
            ];
            *sub_component_inputs.verify_bitwise_xor_8[0] = [
                unsafe { PackedM31::from_simd_unchecked(sw[91]) },
                unsafe { PackedM31::from_simd_unchecked(sw[92]) },
                unsafe { PackedM31::from_simd_unchecked(sw[93]) },
            ];
        });
    (trace, lookup_data, sub_component_inputs)
}

impl ClaimGenerator {
    /// Generic-path counterpart of [`ClaimGenerator::write_trace`]: identical shape, but
    /// the base trace is produced by `write_trace_generic_simd`.
    #[allow(dead_code)]
    pub(crate) fn write_trace_generic(
        self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
        verify_bitwise_xor_9_state: &verify_bitwise_xor_9::ClaimGenerator,
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            log_size,
            self.bitwise_builtin_segment_start,
            memory_address_to_id_state,
            memory_id_to_big_state,
            verify_bitwise_xor_9_state,
            verify_bitwise_xor_8_state,
        );
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
        for inputs in sub_component_inputs.verify_bitwise_xor_9 {
            add_inputs(
                verify_bitwise_xor_9_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
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

/// Record the `bitwise_builtin` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_bitwise_builtin() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("bitwise_builtin", 1, Some(2));
    bitwise_builtin_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    278;
    memory_address_to_id_0: 3,
    memory_id_to_big_1: 30,
    memory_address_to_id_2: 3,
    memory_id_to_big_3: 30,
    verify_bitwise_xor_9_4: 4,
    verify_bitwise_xor_9_5: 4,
    verify_bitwise_xor_9_6: 4,
    verify_bitwise_xor_9_7: 4,
    verify_bitwise_xor_9_8: 4,
    verify_bitwise_xor_9_9: 4,
    verify_bitwise_xor_9_10: 4,
    verify_bitwise_xor_9_11: 4,
    verify_bitwise_xor_9_12: 4,
    verify_bitwise_xor_9_13: 4,
    verify_bitwise_xor_9_14: 4,
    verify_bitwise_xor_9_15: 4,
    verify_bitwise_xor_9_16: 4,
    verify_bitwise_xor_9_17: 4,
    verify_bitwise_xor_9_18: 4,
    verify_bitwise_xor_9_19: 4,
    verify_bitwise_xor_9_20: 4,
    verify_bitwise_xor_9_21: 4,
    verify_bitwise_xor_9_22: 4,
    verify_bitwise_xor_9_23: 4,
    verify_bitwise_xor_9_24: 4,
    verify_bitwise_xor_9_25: 4,
    verify_bitwise_xor_9_26: 4,
    verify_bitwise_xor_9_27: 4,
    verify_bitwise_xor_9_28: 4,
    verify_bitwise_xor_9_29: 4,
    verify_bitwise_xor_9_30: 4,
    verify_bitwise_xor_8_31: 4,
    memory_address_to_id_32: 3,
    memory_id_to_big_33: 30,
    memory_address_to_id_34: 3,
    memory_id_to_big_35: 30,
    memory_address_to_id_36: 3,
    memory_id_to_big_37: 30,
    mults_0: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    (
        "memory_address_to_id",
        0,
        "memory_address_to_id_state",
        0,
        0,
        1,
    ),
    (
        "memory_address_to_id",
        1,
        "memory_address_to_id_state",
        0,
        1,
        1,
    ),
    (
        "memory_address_to_id",
        2,
        "memory_address_to_id_state",
        0,
        2,
        1,
    ),
    (
        "memory_address_to_id",
        3,
        "memory_address_to_id_state",
        0,
        3,
        1,
    ),
    (
        "memory_address_to_id",
        4,
        "memory_address_to_id_state",
        0,
        4,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 5, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 6, 1),
    ("memory_id_to_big", 2, "memory_id_to_big_state", 0, 7, 1),
    ("memory_id_to_big", 3, "memory_id_to_big_state", 0, 8, 1),
    ("memory_id_to_big", 4, "memory_id_to_big_state", 0, 9, 1),
    (
        "verify_bitwise_xor_9",
        0,
        "verify_bitwise_xor_9_state",
        0,
        10,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        1,
        "verify_bitwise_xor_9_state",
        0,
        13,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        2,
        "verify_bitwise_xor_9_state",
        0,
        16,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        3,
        "verify_bitwise_xor_9_state",
        0,
        19,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        4,
        "verify_bitwise_xor_9_state",
        0,
        22,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        5,
        "verify_bitwise_xor_9_state",
        0,
        25,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        6,
        "verify_bitwise_xor_9_state",
        0,
        28,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        7,
        "verify_bitwise_xor_9_state",
        0,
        31,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        8,
        "verify_bitwise_xor_9_state",
        0,
        34,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        9,
        "verify_bitwise_xor_9_state",
        0,
        37,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        10,
        "verify_bitwise_xor_9_state",
        0,
        40,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        11,
        "verify_bitwise_xor_9_state",
        0,
        43,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        12,
        "verify_bitwise_xor_9_state",
        0,
        46,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        13,
        "verify_bitwise_xor_9_state",
        0,
        49,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        14,
        "verify_bitwise_xor_9_state",
        0,
        52,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        15,
        "verify_bitwise_xor_9_state",
        0,
        55,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        16,
        "verify_bitwise_xor_9_state",
        0,
        58,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        17,
        "verify_bitwise_xor_9_state",
        0,
        61,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        18,
        "verify_bitwise_xor_9_state",
        0,
        64,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        19,
        "verify_bitwise_xor_9_state",
        0,
        67,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        20,
        "verify_bitwise_xor_9_state",
        0,
        70,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        21,
        "verify_bitwise_xor_9_state",
        0,
        73,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        22,
        "verify_bitwise_xor_9_state",
        0,
        76,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        23,
        "verify_bitwise_xor_9_state",
        0,
        79,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        24,
        "verify_bitwise_xor_9_state",
        0,
        82,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        25,
        "verify_bitwise_xor_9_state",
        0,
        85,
        3,
    ),
    (
        "verify_bitwise_xor_9",
        26,
        "verify_bitwise_xor_9_state",
        0,
        88,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        0,
        "verify_bitwise_xor_8_state",
        0,
        91,
        3,
    ),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "memory_address_to_id_0",
        "mults_0",
        false,
        "memory_id_to_big_1",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_2",
        "mults_0",
        false,
        "memory_id_to_big_3",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_4",
        "mults_0",
        false,
        "verify_bitwise_xor_9_5",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_6",
        "mults_0",
        false,
        "verify_bitwise_xor_9_7",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_8",
        "mults_0",
        false,
        "verify_bitwise_xor_9_9",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_10",
        "mults_0",
        false,
        "verify_bitwise_xor_9_11",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_12",
        "mults_0",
        false,
        "verify_bitwise_xor_9_13",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_14",
        "mults_0",
        false,
        "verify_bitwise_xor_9_15",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_16",
        "mults_0",
        false,
        "verify_bitwise_xor_9_17",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_18",
        "mults_0",
        false,
        "verify_bitwise_xor_9_19",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_20",
        "mults_0",
        false,
        "verify_bitwise_xor_9_21",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_22",
        "mults_0",
        false,
        "verify_bitwise_xor_9_23",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_24",
        "mults_0",
        false,
        "verify_bitwise_xor_9_25",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_26",
        "mults_0",
        false,
        "verify_bitwise_xor_9_27",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_28",
        "mults_0",
        false,
        "verify_bitwise_xor_9_29",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_9_30",
        "mults_0",
        false,
        "verify_bitwise_xor_8_31",
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
        "memory_address_to_id_34",
        "mults_0",
        false,
        "memory_id_to_big_35",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_36",
        "mults_0",
        false,
        "memory_id_to_big_37",
        "mults_0",
        false,
    ),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.memory_address_to_id_0
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_1.iter().flatten().copied().collect(),
        ld.memory_address_to_id_2
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_3.iter().flatten().copied().collect(),
        ld.verify_bitwise_xor_9_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_6
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_7
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_8
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_9
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_10
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_11
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_12
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_13
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_14
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_15
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_16
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_17
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_18
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_19
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_20
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_21
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_22
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_23
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_24
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_25
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_26
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_27
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_28
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_29
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_9_30
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_31
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_32
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_33.iter().flatten().copied().collect(),
        ld.memory_address_to_id_34
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_35.iter().flatten().copied().collect(),
        ld.memory_address_to_id_36
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_37.iter().flatten().copied().collect(),
        ld.mults_0.clone(),
    ]
}

#[cfg(test)]
pub(crate) fn test_lookup_data_flat(ig: &InteractionClaimGenerator) -> Vec<Vec<PackedM31>> {
    lookup_data_flat(&ig.lookup_data)
}

fn sub_inputs_flat(sci: &SubComponentInputs) -> Vec<Vec<Simd<u32, N_LANES>>> {
    vec![
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
        sci.verify_bitwise_xor_9[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[7]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[8]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[9]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[10]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[11]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[12]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[13]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[14]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[15]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[16]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[17]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[18]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[19]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[20]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[21]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[22]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[23]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[24]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[25]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_9[26]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
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
    log_size: u32,
    bitwise_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    verify_bitwise_xor_9_state: &verify_bitwise_xor_9::ClaimGenerator,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        log_size.clone(),
        bitwise_builtin_segment_start.clone(),
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_bitwise_xor_9_state,
        verify_bitwise_xor_8_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        log_size,
        bitwise_builtin_segment_start,
        memory_address_to_id_state,
        memory_id_to_big_state,
        verify_bitwise_xor_9_state,
        verify_bitwise_xor_8_state,
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
    memory_address_to_id_0: Vec<[PackedM31; 3]>,
    memory_id_to_big_1: Vec<[PackedM31; 30]>,
    memory_address_to_id_2: Vec<[PackedM31; 3]>,
    memory_id_to_big_3: Vec<[PackedM31; 30]>,
    verify_bitwise_xor_9_4: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_5: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_6: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_7: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_8: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_9: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_10: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_11: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_12: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_13: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_14: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_15: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_16: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_17: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_18: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_19: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_20: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_21: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_22: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_23: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_24: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_25: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_26: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_27: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_28: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_29: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_9_30: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_31: Vec<[PackedM31; 4]>,
    memory_address_to_id_32: Vec<[PackedM31; 3]>,
    memory_id_to_big_33: Vec<[PackedM31; 30]>,
    memory_address_to_id_34: Vec<[PackedM31; 3]>,
    memory_id_to_big_35: Vec<[PackedM31; 30]>,
    memory_address_to_id_36: Vec<[PackedM31; 3]>,
    memory_id_to_big_37: Vec<[PackedM31; 30]>,
    mults_0: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    memory_address_to_id_0: 3,
    memory_id_to_big_1: 30,
    memory_address_to_id_2: 3,
    memory_id_to_big_3: 30,
    verify_bitwise_xor_9_4: 4,
    verify_bitwise_xor_9_5: 4,
    verify_bitwise_xor_9_6: 4,
    verify_bitwise_xor_9_7: 4,
    verify_bitwise_xor_9_8: 4,
    verify_bitwise_xor_9_9: 4,
    verify_bitwise_xor_9_10: 4,
    verify_bitwise_xor_9_11: 4,
    verify_bitwise_xor_9_12: 4,
    verify_bitwise_xor_9_13: 4,
    verify_bitwise_xor_9_14: 4,
    verify_bitwise_xor_9_15: 4,
    verify_bitwise_xor_9_16: 4,
    verify_bitwise_xor_9_17: 4,
    verify_bitwise_xor_9_18: 4,
    verify_bitwise_xor_9_19: 4,
    verify_bitwise_xor_9_20: 4,
    verify_bitwise_xor_9_21: 4,
    verify_bitwise_xor_9_22: 4,
    verify_bitwise_xor_9_23: 4,
    verify_bitwise_xor_9_24: 4,
    verify_bitwise_xor_9_25: 4,
    verify_bitwise_xor_9_26: 4,
    verify_bitwise_xor_9_27: 4,
    verify_bitwise_xor_9_28: 4,
    verify_bitwise_xor_9_29: 4,
    verify_bitwise_xor_9_30: 4,
    verify_bitwise_xor_8_31: 4,
    memory_address_to_id_32: 3,
    memory_id_to_big_33: 30,
    memory_address_to_id_34: 3,
    memory_id_to_big_35: 30,
    memory_address_to_id_36: 3,
    memory_id_to_big_37: 30,
    mults_0: scalar,
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
            &self.lookup_data.memory_address_to_id_0,
            &self.lookup_data.memory_id_to_big_1,
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
            &self.lookup_data.memory_address_to_id_2,
            &self.lookup_data.memory_id_to_big_3,
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
            &self.lookup_data.verify_bitwise_xor_9_4,
            &self.lookup_data.verify_bitwise_xor_9_5,
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
            &self.lookup_data.verify_bitwise_xor_9_6,
            &self.lookup_data.verify_bitwise_xor_9_7,
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
            &self.lookup_data.verify_bitwise_xor_9_8,
            &self.lookup_data.verify_bitwise_xor_9_9,
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
            &self.lookup_data.verify_bitwise_xor_9_10,
            &self.lookup_data.verify_bitwise_xor_9_11,
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
            &self.lookup_data.verify_bitwise_xor_9_12,
            &self.lookup_data.verify_bitwise_xor_9_13,
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
            &self.lookup_data.verify_bitwise_xor_9_14,
            &self.lookup_data.verify_bitwise_xor_9_15,
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
            &self.lookup_data.verify_bitwise_xor_9_16,
            &self.lookup_data.verify_bitwise_xor_9_17,
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
            &self.lookup_data.verify_bitwise_xor_9_18,
            &self.lookup_data.verify_bitwise_xor_9_19,
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
            &self.lookup_data.verify_bitwise_xor_9_20,
            &self.lookup_data.verify_bitwise_xor_9_21,
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
            &self.lookup_data.verify_bitwise_xor_9_22,
            &self.lookup_data.verify_bitwise_xor_9_23,
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
            &self.lookup_data.verify_bitwise_xor_9_24,
            &self.lookup_data.verify_bitwise_xor_9_25,
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
            &self.lookup_data.verify_bitwise_xor_9_26,
            &self.lookup_data.verify_bitwise_xor_9_27,
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
            &self.lookup_data.verify_bitwise_xor_9_28,
            &self.lookup_data.verify_bitwise_xor_9_29,
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
            &self.lookup_data.verify_bitwise_xor_9_30,
            &self.lookup_data.verify_bitwise_xor_8_31,
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
            &self.lookup_data.memory_address_to_id_34,
            &self.lookup_data.memory_id_to_big_35,
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
            &self.lookup_data.memory_address_to_id_36,
            &self.lookup_data.memory_id_to_big_37,
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

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
