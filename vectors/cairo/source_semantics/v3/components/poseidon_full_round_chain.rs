// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::poseidon_full_round_chain::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{cube_252, poseidon_round_keys, range_check_3_3_3_3_3};
use crate::witness::prelude::*;

pub type InputType = (M31, M31, [Felt252Width27; 3]);
pub type PackedInputType = (PackedM31, PackedM31, [PackedFelt252Width27; 3]);

#[derive(Default)]
pub struct ClaimGenerator {
    pub packed_inputs: Mutex<Vec<PackedInputType>>,
    pub remainder_inputs: Mutex<Vec<InputType>>,
}

impl ClaimGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_trace(
        self,
        cube_252_state: &cube_252::ClaimGenerator,
        poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
        range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut packed_inputs = self.packed_inputs.into_inner().unwrap();
        assert!(!packed_inputs.is_empty());
        assert!(self.remainder_inputs.lock().unwrap().is_empty());
        let n_vec_rows = packed_inputs.len();
        let n_rows = n_vec_rows * N_LANES;
        let packed_size = n_vec_rows.next_power_of_two();
        let log_size = packed_size.ilog2() + LOG_N_LANES;
        packed_inputs.resize(packed_size, *packed_inputs.first().unwrap());

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            packed_inputs,
            n_rows,
            cube_252_state,
            poseidon_round_keys_state,
            range_check_3_3_3_3_3_state,
        );
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_round_keys {
            add_inputs(
                poseidon_round_keys_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_3_3_3_3_3 {
            add_inputs(
                range_check_3_3_3_3_3_state,
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

impl AddInputs for ClaimGenerator {
    type PackedInputType = PackedInputType;
    type InputType = InputType;

    fn add_packed_inputs(&self, inputs: &[PackedInputType], _relation_index: usize) {
        self.packed_inputs.lock().unwrap().extend(inputs);
    }
    fn add_input(&self, input: &InputType, _relation_index: usize) {
        self.remainder_inputs.lock().unwrap().push(*input);
    }
}

#[derive(Uninitialized, IterMut, ParIterMut)]
struct SubComponentInputs {
    cube_252: [Vec<cube_252::PackedInputType>; 3],
    poseidon_round_keys: [Vec<poseidon_round_keys::PackedInputType>; 1],
    range_check_3_3_3_3_3: [Vec<range_check_3_3_3_3_3::PackedInputType>; 6],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    cube_252_state: &cube_252::ClaimGenerator,
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
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

    let Felt252_0_0_0_0 = PackedFelt252::broadcast(Felt252::from([0, 0, 0, 0]));
    let Felt252_1_0_0_0 = PackedFelt252::broadcast(Felt252::from([1, 0, 0, 0]));
    let Felt252_2_0_0_0 = PackedFelt252::broadcast(Felt252::from([2, 0, 0, 0]));
    let Felt252_3_0_0_0 = PackedFelt252::broadcast(Felt252::from([3, 0, 0, 0]));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1024310512 = PackedM31::broadcast(M31::from(1024310512));
    let M31_134217729 = PackedM31::broadcast(M31::from(134217729));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1480369132 = PackedM31::broadcast(M31::from(1480369132));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1987997202 = PackedM31::broadcast(M31::from(1987997202));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_268435458 = PackedM31::broadcast(M31::from(268435458));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_402653187 = PackedM31::broadcast(M31::from(402653187));
    let M31_502259093 = PackedM31::broadcast(M31::from(502259093));
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
            |(
                row_index,
                (row, lookup_data, sub_component_inputs, poseidon_full_round_chain_input),
            )| {
                let input_limb_0_col0 = poseidon_full_round_chain_input.0;
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = poseidon_full_round_chain_input.1;
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = poseidon_full_round_chain_input.2[0].get_m31(0);
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = poseidon_full_round_chain_input.2[0].get_m31(1);
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = poseidon_full_round_chain_input.2[0].get_m31(2);
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = poseidon_full_round_chain_input.2[0].get_m31(3);
                *row[5] = input_limb_5_col5;
                let input_limb_6_col6 = poseidon_full_round_chain_input.2[0].get_m31(4);
                *row[6] = input_limb_6_col6;
                let input_limb_7_col7 = poseidon_full_round_chain_input.2[0].get_m31(5);
                *row[7] = input_limb_7_col7;
                let input_limb_8_col8 = poseidon_full_round_chain_input.2[0].get_m31(6);
                *row[8] = input_limb_8_col8;
                let input_limb_9_col9 = poseidon_full_round_chain_input.2[0].get_m31(7);
                *row[9] = input_limb_9_col9;
                let input_limb_10_col10 = poseidon_full_round_chain_input.2[0].get_m31(8);
                *row[10] = input_limb_10_col10;
                let input_limb_11_col11 = poseidon_full_round_chain_input.2[0].get_m31(9);
                *row[11] = input_limb_11_col11;
                let input_limb_12_col12 = poseidon_full_round_chain_input.2[1].get_m31(0);
                *row[12] = input_limb_12_col12;
                let input_limb_13_col13 = poseidon_full_round_chain_input.2[1].get_m31(1);
                *row[13] = input_limb_13_col13;
                let input_limb_14_col14 = poseidon_full_round_chain_input.2[1].get_m31(2);
                *row[14] = input_limb_14_col14;
                let input_limb_15_col15 = poseidon_full_round_chain_input.2[1].get_m31(3);
                *row[15] = input_limb_15_col15;
                let input_limb_16_col16 = poseidon_full_round_chain_input.2[1].get_m31(4);
                *row[16] = input_limb_16_col16;
                let input_limb_17_col17 = poseidon_full_round_chain_input.2[1].get_m31(5);
                *row[17] = input_limb_17_col17;
                let input_limb_18_col18 = poseidon_full_round_chain_input.2[1].get_m31(6);
                *row[18] = input_limb_18_col18;
                let input_limb_19_col19 = poseidon_full_round_chain_input.2[1].get_m31(7);
                *row[19] = input_limb_19_col19;
                let input_limb_20_col20 = poseidon_full_round_chain_input.2[1].get_m31(8);
                *row[20] = input_limb_20_col20;
                let input_limb_21_col21 = poseidon_full_round_chain_input.2[1].get_m31(9);
                *row[21] = input_limb_21_col21;
                let input_limb_22_col22 = poseidon_full_round_chain_input.2[2].get_m31(0);
                *row[22] = input_limb_22_col22;
                let input_limb_23_col23 = poseidon_full_round_chain_input.2[2].get_m31(1);
                *row[23] = input_limb_23_col23;
                let input_limb_24_col24 = poseidon_full_round_chain_input.2[2].get_m31(2);
                *row[24] = input_limb_24_col24;
                let input_limb_25_col25 = poseidon_full_round_chain_input.2[2].get_m31(3);
                *row[25] = input_limb_25_col25;
                let input_limb_26_col26 = poseidon_full_round_chain_input.2[2].get_m31(4);
                *row[26] = input_limb_26_col26;
                let input_limb_27_col27 = poseidon_full_round_chain_input.2[2].get_m31(5);
                *row[27] = input_limb_27_col27;
                let input_limb_28_col28 = poseidon_full_round_chain_input.2[2].get_m31(6);
                *row[28] = input_limb_28_col28;
                let input_limb_29_col29 = poseidon_full_round_chain_input.2[2].get_m31(7);
                *row[29] = input_limb_29_col29;
                let input_limb_30_col30 = poseidon_full_round_chain_input.2[2].get_m31(8);
                *row[30] = input_limb_30_col30;
                let input_limb_31_col31 = poseidon_full_round_chain_input.2[2].get_m31(9);
                *row[31] = input_limb_31_col31;
                *sub_component_inputs.cube_252[0] = poseidon_full_round_chain_input.2[0];
                let cube_252_output_tmp_1400f_0 =
                    PackedCube252::deduce_output(poseidon_full_round_chain_input.2[0]);
                let cube_252_output_limb_0_col32 = cube_252_output_tmp_1400f_0.get_m31(0);
                *row[32] = cube_252_output_limb_0_col32;
                let cube_252_output_limb_1_col33 = cube_252_output_tmp_1400f_0.get_m31(1);
                *row[33] = cube_252_output_limb_1_col33;
                let cube_252_output_limb_2_col34 = cube_252_output_tmp_1400f_0.get_m31(2);
                *row[34] = cube_252_output_limb_2_col34;
                let cube_252_output_limb_3_col35 = cube_252_output_tmp_1400f_0.get_m31(3);
                *row[35] = cube_252_output_limb_3_col35;
                let cube_252_output_limb_4_col36 = cube_252_output_tmp_1400f_0.get_m31(4);
                *row[36] = cube_252_output_limb_4_col36;
                let cube_252_output_limb_5_col37 = cube_252_output_tmp_1400f_0.get_m31(5);
                *row[37] = cube_252_output_limb_5_col37;
                let cube_252_output_limb_6_col38 = cube_252_output_tmp_1400f_0.get_m31(6);
                *row[38] = cube_252_output_limb_6_col38;
                let cube_252_output_limb_7_col39 = cube_252_output_tmp_1400f_0.get_m31(7);
                *row[39] = cube_252_output_limb_7_col39;
                let cube_252_output_limb_8_col40 = cube_252_output_tmp_1400f_0.get_m31(8);
                *row[40] = cube_252_output_limb_8_col40;
                let cube_252_output_limb_9_col41 = cube_252_output_tmp_1400f_0.get_m31(9);
                *row[41] = cube_252_output_limb_9_col41;
                *lookup_data.cube_252_0 = [
                    M31_1987997202,
                    input_limb_2_col2,
                    input_limb_3_col3,
                    input_limb_4_col4,
                    input_limb_5_col5,
                    input_limb_6_col6,
                    input_limb_7_col7,
                    input_limb_8_col8,
                    input_limb_9_col9,
                    input_limb_10_col10,
                    input_limb_11_col11,
                    cube_252_output_limb_0_col32,
                    cube_252_output_limb_1_col33,
                    cube_252_output_limb_2_col34,
                    cube_252_output_limb_3_col35,
                    cube_252_output_limb_4_col36,
                    cube_252_output_limb_5_col37,
                    cube_252_output_limb_6_col38,
                    cube_252_output_limb_7_col39,
                    cube_252_output_limb_8_col40,
                    cube_252_output_limb_9_col41,
                ];
                *sub_component_inputs.cube_252[1] = poseidon_full_round_chain_input.2[1];
                let cube_252_output_tmp_1400f_1 =
                    PackedCube252::deduce_output(poseidon_full_round_chain_input.2[1]);
                let cube_252_output_limb_0_col42 = cube_252_output_tmp_1400f_1.get_m31(0);
                *row[42] = cube_252_output_limb_0_col42;
                let cube_252_output_limb_1_col43 = cube_252_output_tmp_1400f_1.get_m31(1);
                *row[43] = cube_252_output_limb_1_col43;
                let cube_252_output_limb_2_col44 = cube_252_output_tmp_1400f_1.get_m31(2);
                *row[44] = cube_252_output_limb_2_col44;
                let cube_252_output_limb_3_col45 = cube_252_output_tmp_1400f_1.get_m31(3);
                *row[45] = cube_252_output_limb_3_col45;
                let cube_252_output_limb_4_col46 = cube_252_output_tmp_1400f_1.get_m31(4);
                *row[46] = cube_252_output_limb_4_col46;
                let cube_252_output_limb_5_col47 = cube_252_output_tmp_1400f_1.get_m31(5);
                *row[47] = cube_252_output_limb_5_col47;
                let cube_252_output_limb_6_col48 = cube_252_output_tmp_1400f_1.get_m31(6);
                *row[48] = cube_252_output_limb_6_col48;
                let cube_252_output_limb_7_col49 = cube_252_output_tmp_1400f_1.get_m31(7);
                *row[49] = cube_252_output_limb_7_col49;
                let cube_252_output_limb_8_col50 = cube_252_output_tmp_1400f_1.get_m31(8);
                *row[50] = cube_252_output_limb_8_col50;
                let cube_252_output_limb_9_col51 = cube_252_output_tmp_1400f_1.get_m31(9);
                *row[51] = cube_252_output_limb_9_col51;
                *lookup_data.cube_252_1 = [
                    M31_1987997202,
                    input_limb_12_col12,
                    input_limb_13_col13,
                    input_limb_14_col14,
                    input_limb_15_col15,
                    input_limb_16_col16,
                    input_limb_17_col17,
                    input_limb_18_col18,
                    input_limb_19_col19,
                    input_limb_20_col20,
                    input_limb_21_col21,
                    cube_252_output_limb_0_col42,
                    cube_252_output_limb_1_col43,
                    cube_252_output_limb_2_col44,
                    cube_252_output_limb_3_col45,
                    cube_252_output_limb_4_col46,
                    cube_252_output_limb_5_col47,
                    cube_252_output_limb_6_col48,
                    cube_252_output_limb_7_col49,
                    cube_252_output_limb_8_col50,
                    cube_252_output_limb_9_col51,
                ];
                *sub_component_inputs.cube_252[2] = poseidon_full_round_chain_input.2[2];
                let cube_252_output_tmp_1400f_2 =
                    PackedCube252::deduce_output(poseidon_full_round_chain_input.2[2]);
                let cube_252_output_limb_0_col52 = cube_252_output_tmp_1400f_2.get_m31(0);
                *row[52] = cube_252_output_limb_0_col52;
                let cube_252_output_limb_1_col53 = cube_252_output_tmp_1400f_2.get_m31(1);
                *row[53] = cube_252_output_limb_1_col53;
                let cube_252_output_limb_2_col54 = cube_252_output_tmp_1400f_2.get_m31(2);
                *row[54] = cube_252_output_limb_2_col54;
                let cube_252_output_limb_3_col55 = cube_252_output_tmp_1400f_2.get_m31(3);
                *row[55] = cube_252_output_limb_3_col55;
                let cube_252_output_limb_4_col56 = cube_252_output_tmp_1400f_2.get_m31(4);
                *row[56] = cube_252_output_limb_4_col56;
                let cube_252_output_limb_5_col57 = cube_252_output_tmp_1400f_2.get_m31(5);
                *row[57] = cube_252_output_limb_5_col57;
                let cube_252_output_limb_6_col58 = cube_252_output_tmp_1400f_2.get_m31(6);
                *row[58] = cube_252_output_limb_6_col58;
                let cube_252_output_limb_7_col59 = cube_252_output_tmp_1400f_2.get_m31(7);
                *row[59] = cube_252_output_limb_7_col59;
                let cube_252_output_limb_8_col60 = cube_252_output_tmp_1400f_2.get_m31(8);
                *row[60] = cube_252_output_limb_8_col60;
                let cube_252_output_limb_9_col61 = cube_252_output_tmp_1400f_2.get_m31(9);
                *row[61] = cube_252_output_limb_9_col61;
                *lookup_data.cube_252_2 = [
                    M31_1987997202,
                    input_limb_22_col22,
                    input_limb_23_col23,
                    input_limb_24_col24,
                    input_limb_25_col25,
                    input_limb_26_col26,
                    input_limb_27_col27,
                    input_limb_28_col28,
                    input_limb_29_col29,
                    input_limb_30_col30,
                    input_limb_31_col31,
                    cube_252_output_limb_0_col52,
                    cube_252_output_limb_1_col53,
                    cube_252_output_limb_2_col54,
                    cube_252_output_limb_3_col55,
                    cube_252_output_limb_4_col56,
                    cube_252_output_limb_5_col57,
                    cube_252_output_limb_6_col58,
                    cube_252_output_limb_7_col59,
                    cube_252_output_limb_8_col60,
                    cube_252_output_limb_9_col61,
                ];
                *sub_component_inputs.poseidon_round_keys[0] = [input_limb_1_col1];
                let poseidon_round_keys_output_tmp_1400f_3 =
                    PackedPoseidonRoundKeys::deduce_output([input_limb_1_col1]);
                let poseidon_round_keys_output_limb_0_col62 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(0);
                *row[62] = poseidon_round_keys_output_limb_0_col62;
                let poseidon_round_keys_output_limb_1_col63 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(1);
                *row[63] = poseidon_round_keys_output_limb_1_col63;
                let poseidon_round_keys_output_limb_2_col64 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(2);
                *row[64] = poseidon_round_keys_output_limb_2_col64;
                let poseidon_round_keys_output_limb_3_col65 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(3);
                *row[65] = poseidon_round_keys_output_limb_3_col65;
                let poseidon_round_keys_output_limb_4_col66 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(4);
                *row[66] = poseidon_round_keys_output_limb_4_col66;
                let poseidon_round_keys_output_limb_5_col67 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(5);
                *row[67] = poseidon_round_keys_output_limb_5_col67;
                let poseidon_round_keys_output_limb_6_col68 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(6);
                *row[68] = poseidon_round_keys_output_limb_6_col68;
                let poseidon_round_keys_output_limb_7_col69 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(7);
                *row[69] = poseidon_round_keys_output_limb_7_col69;
                let poseidon_round_keys_output_limb_8_col70 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(8);
                *row[70] = poseidon_round_keys_output_limb_8_col70;
                let poseidon_round_keys_output_limb_9_col71 =
                    poseidon_round_keys_output_tmp_1400f_3[0].get_m31(9);
                *row[71] = poseidon_round_keys_output_limb_9_col71;
                let poseidon_round_keys_output_limb_10_col72 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(0);
                *row[72] = poseidon_round_keys_output_limb_10_col72;
                let poseidon_round_keys_output_limb_11_col73 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(1);
                *row[73] = poseidon_round_keys_output_limb_11_col73;
                let poseidon_round_keys_output_limb_12_col74 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(2);
                *row[74] = poseidon_round_keys_output_limb_12_col74;
                let poseidon_round_keys_output_limb_13_col75 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(3);
                *row[75] = poseidon_round_keys_output_limb_13_col75;
                let poseidon_round_keys_output_limb_14_col76 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(4);
                *row[76] = poseidon_round_keys_output_limb_14_col76;
                let poseidon_round_keys_output_limb_15_col77 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(5);
                *row[77] = poseidon_round_keys_output_limb_15_col77;
                let poseidon_round_keys_output_limb_16_col78 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(6);
                *row[78] = poseidon_round_keys_output_limb_16_col78;
                let poseidon_round_keys_output_limb_17_col79 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(7);
                *row[79] = poseidon_round_keys_output_limb_17_col79;
                let poseidon_round_keys_output_limb_18_col80 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(8);
                *row[80] = poseidon_round_keys_output_limb_18_col80;
                let poseidon_round_keys_output_limb_19_col81 =
                    poseidon_round_keys_output_tmp_1400f_3[1].get_m31(9);
                *row[81] = poseidon_round_keys_output_limb_19_col81;
                let poseidon_round_keys_output_limb_20_col82 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(0);
                *row[82] = poseidon_round_keys_output_limb_20_col82;
                let poseidon_round_keys_output_limb_21_col83 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(1);
                *row[83] = poseidon_round_keys_output_limb_21_col83;
                let poseidon_round_keys_output_limb_22_col84 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(2);
                *row[84] = poseidon_round_keys_output_limb_22_col84;
                let poseidon_round_keys_output_limb_23_col85 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(3);
                *row[85] = poseidon_round_keys_output_limb_23_col85;
                let poseidon_round_keys_output_limb_24_col86 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(4);
                *row[86] = poseidon_round_keys_output_limb_24_col86;
                let poseidon_round_keys_output_limb_25_col87 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(5);
                *row[87] = poseidon_round_keys_output_limb_25_col87;
                let poseidon_round_keys_output_limb_26_col88 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(6);
                *row[88] = poseidon_round_keys_output_limb_26_col88;
                let poseidon_round_keys_output_limb_27_col89 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(7);
                *row[89] = poseidon_round_keys_output_limb_27_col89;
                let poseidon_round_keys_output_limb_28_col90 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(8);
                *row[90] = poseidon_round_keys_output_limb_28_col90;
                let poseidon_round_keys_output_limb_29_col91 =
                    poseidon_round_keys_output_tmp_1400f_3[2].get_m31(9);
                *row[91] = poseidon_round_keys_output_limb_29_col91;
                *lookup_data.poseidon_round_keys_3 = [
                    M31_1024310512,
                    input_limb_1_col1,
                    poseidon_round_keys_output_limb_0_col62,
                    poseidon_round_keys_output_limb_1_col63,
                    poseidon_round_keys_output_limb_2_col64,
                    poseidon_round_keys_output_limb_3_col65,
                    poseidon_round_keys_output_limb_4_col66,
                    poseidon_round_keys_output_limb_5_col67,
                    poseidon_round_keys_output_limb_6_col68,
                    poseidon_round_keys_output_limb_7_col69,
                    poseidon_round_keys_output_limb_8_col70,
                    poseidon_round_keys_output_limb_9_col71,
                    poseidon_round_keys_output_limb_10_col72,
                    poseidon_round_keys_output_limb_11_col73,
                    poseidon_round_keys_output_limb_12_col74,
                    poseidon_round_keys_output_limb_13_col75,
                    poseidon_round_keys_output_limb_14_col76,
                    poseidon_round_keys_output_limb_15_col77,
                    poseidon_round_keys_output_limb_16_col78,
                    poseidon_round_keys_output_limb_17_col79,
                    poseidon_round_keys_output_limb_18_col80,
                    poseidon_round_keys_output_limb_19_col81,
                    poseidon_round_keys_output_limb_20_col82,
                    poseidon_round_keys_output_limb_21_col83,
                    poseidon_round_keys_output_limb_22_col84,
                    poseidon_round_keys_output_limb_23_col85,
                    poseidon_round_keys_output_limb_24_col86,
                    poseidon_round_keys_output_limb_25_col87,
                    poseidon_round_keys_output_limb_26_col88,
                    poseidon_round_keys_output_limb_27_col89,
                    poseidon_round_keys_output_limb_28_col90,
                    poseidon_round_keys_output_limb_29_col91,
                ];

                // Linear Combination N 4 Coefs 3 1 1 1.

                let combination_tmp_1400f_4 = PackedFelt252Width27::from_packed_felt252(
                    (((((Felt252_0_0_0_0)
                        + ((Felt252_3_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_0,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_1,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_2,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_1400f_3[0],
                            )))),
                );
                let combination_limb_0_col92 = combination_tmp_1400f_4.get_m31(0);
                *row[92] = combination_limb_0_col92;
                let combination_limb_1_col93 = combination_tmp_1400f_4.get_m31(1);
                *row[93] = combination_limb_1_col93;
                let combination_limb_2_col94 = combination_tmp_1400f_4.get_m31(2);
                *row[94] = combination_limb_2_col94;
                let combination_limb_3_col95 = combination_tmp_1400f_4.get_m31(3);
                *row[95] = combination_limb_3_col95;
                let combination_limb_4_col96 = combination_tmp_1400f_4.get_m31(4);
                *row[96] = combination_limb_4_col96;
                let combination_limb_5_col97 = combination_tmp_1400f_4.get_m31(5);
                *row[97] = combination_limb_5_col97;
                let combination_limb_6_col98 = combination_tmp_1400f_4.get_m31(6);
                *row[98] = combination_limb_6_col98;
                let combination_limb_7_col99 = combination_tmp_1400f_4.get_m31(7);
                *row[99] = combination_limb_7_col99;
                let combination_limb_8_col100 = combination_tmp_1400f_4.get_m31(8);
                *row[100] = combination_limb_8_col100;
                let combination_limb_9_col101 = combination_tmp_1400f_4.get_m31(9);
                *row[101] = combination_limb_9_col101;
                let biased_limb_accumulator_u32_tmp_1400f_5 = PackedUInt32::from_m31(
                    (((((((M31_3) * (cube_252_output_limb_0_col32))
                        + (cube_252_output_limb_0_col42))
                        + (cube_252_output_limb_0_col52))
                        + (poseidon_round_keys_output_limb_0_col62))
                        - (combination_limb_0_col92))
                        + (M31_134217729)),
                );
                let p_coef_col102 =
                    ((biased_limb_accumulator_u32_tmp_1400f_5.low().as_m31()) - (M31_1));
                *row[102] = p_coef_col102;
                let carry_0_tmp_1400f_6 = ((((((((M31_3) * (cube_252_output_limb_0_col32))
                    + (cube_252_output_limb_0_col42))
                    + (cube_252_output_limb_0_col52))
                    + (poseidon_round_keys_output_limb_0_col62))
                    - (combination_limb_0_col92))
                    - (p_coef_col102))
                    * (M31_16));
                let carry_1_tmp_1400f_7 = (((((((carry_0_tmp_1400f_6)
                    + ((M31_3) * (cube_252_output_limb_1_col33)))
                    + (cube_252_output_limb_1_col43))
                    + (cube_252_output_limb_1_col53))
                    + (poseidon_round_keys_output_limb_1_col63))
                    - (combination_limb_1_col93))
                    * (M31_16));
                let carry_2_tmp_1400f_8 = (((((((carry_1_tmp_1400f_7)
                    + ((M31_3) * (cube_252_output_limb_2_col34)))
                    + (cube_252_output_limb_2_col44))
                    + (cube_252_output_limb_2_col54))
                    + (poseidon_round_keys_output_limb_2_col64))
                    - (combination_limb_2_col94))
                    * (M31_16));
                let carry_3_tmp_1400f_9 = (((((((carry_2_tmp_1400f_8)
                    + ((M31_3) * (cube_252_output_limb_3_col35)))
                    + (cube_252_output_limb_3_col45))
                    + (cube_252_output_limb_3_col55))
                    + (poseidon_round_keys_output_limb_3_col65))
                    - (combination_limb_3_col95))
                    * (M31_16));
                let carry_4_tmp_1400f_10 = (((((((carry_3_tmp_1400f_9)
                    + ((M31_3) * (cube_252_output_limb_4_col36)))
                    + (cube_252_output_limb_4_col46))
                    + (cube_252_output_limb_4_col56))
                    + (poseidon_round_keys_output_limb_4_col66))
                    - (combination_limb_4_col96))
                    * (M31_16));
                let carry_5_tmp_1400f_11 = (((((((carry_4_tmp_1400f_10)
                    + ((M31_3) * (cube_252_output_limb_5_col37)))
                    + (cube_252_output_limb_5_col47))
                    + (cube_252_output_limb_5_col57))
                    + (poseidon_round_keys_output_limb_5_col67))
                    - (combination_limb_5_col97))
                    * (M31_16));
                let carry_6_tmp_1400f_12 = (((((((carry_5_tmp_1400f_11)
                    + ((M31_3) * (cube_252_output_limb_6_col38)))
                    + (cube_252_output_limb_6_col48))
                    + (cube_252_output_limb_6_col58))
                    + (poseidon_round_keys_output_limb_6_col68))
                    - (combination_limb_6_col98))
                    * (M31_16));
                let carry_7_tmp_1400f_13 = ((((((((carry_6_tmp_1400f_12)
                    + ((M31_3) * (cube_252_output_limb_7_col39)))
                    + (cube_252_output_limb_7_col49))
                    + (cube_252_output_limb_7_col59))
                    + (poseidon_round_keys_output_limb_7_col69))
                    - (combination_limb_7_col99))
                    - ((p_coef_col102) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_1400f_14 = (((((((carry_7_tmp_1400f_13)
                    + ((M31_3) * (cube_252_output_limb_8_col40)))
                    + (cube_252_output_limb_8_col50))
                    + (cube_252_output_limb_8_col60))
                    + (poseidon_round_keys_output_limb_8_col70))
                    - (combination_limb_8_col100))
                    * (M31_16));
                *sub_component_inputs.range_check_3_3_3_3_3[0] = [
                    ((p_coef_col102) + (M31_1)),
                    ((carry_0_tmp_1400f_6) + (M31_1)),
                    ((carry_1_tmp_1400f_7) + (M31_1)),
                    ((carry_2_tmp_1400f_8) + (M31_1)),
                    ((carry_3_tmp_1400f_9) + (M31_1)),
                ];
                *lookup_data.range_check_3_3_3_3_3_4 = [
                    M31_502259093,
                    ((p_coef_col102) + (M31_1)),
                    ((carry_0_tmp_1400f_6) + (M31_1)),
                    ((carry_1_tmp_1400f_7) + (M31_1)),
                    ((carry_2_tmp_1400f_8) + (M31_1)),
                    ((carry_3_tmp_1400f_9) + (M31_1)),
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[1] = [
                    ((carry_4_tmp_1400f_10) + (M31_1)),
                    ((carry_5_tmp_1400f_11) + (M31_1)),
                    ((carry_6_tmp_1400f_12) + (M31_1)),
                    ((carry_7_tmp_1400f_13) + (M31_1)),
                    ((carry_8_tmp_1400f_14) + (M31_1)),
                ];
                *lookup_data.range_check_3_3_3_3_3_5 = [
                    M31_502259093,
                    ((carry_4_tmp_1400f_10) + (M31_1)),
                    ((carry_5_tmp_1400f_11) + (M31_1)),
                    ((carry_6_tmp_1400f_12) + (M31_1)),
                    ((carry_7_tmp_1400f_13) + (M31_1)),
                    ((carry_8_tmp_1400f_14) + (M31_1)),
                ];
                let linear_combination_n_4_coefs_3_1_1_1_output_tmp_1400f_15 =
                    combination_tmp_1400f_4;

                // Linear Combination N 4 Coefs 1 M 1 1 1.

                let combination_tmp_1400f_16 = PackedFelt252Width27::from_packed_felt252(
                    (((((Felt252_0_0_0_0)
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_0,
                            ))))
                        - ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_1,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_2,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_1400f_3[1],
                            )))),
                );
                let combination_limb_0_col103 = combination_tmp_1400f_16.get_m31(0);
                *row[103] = combination_limb_0_col103;
                let combination_limb_1_col104 = combination_tmp_1400f_16.get_m31(1);
                *row[104] = combination_limb_1_col104;
                let combination_limb_2_col105 = combination_tmp_1400f_16.get_m31(2);
                *row[105] = combination_limb_2_col105;
                let combination_limb_3_col106 = combination_tmp_1400f_16.get_m31(3);
                *row[106] = combination_limb_3_col106;
                let combination_limb_4_col107 = combination_tmp_1400f_16.get_m31(4);
                *row[107] = combination_limb_4_col107;
                let combination_limb_5_col108 = combination_tmp_1400f_16.get_m31(5);
                *row[108] = combination_limb_5_col108;
                let combination_limb_6_col109 = combination_tmp_1400f_16.get_m31(6);
                *row[109] = combination_limb_6_col109;
                let combination_limb_7_col110 = combination_tmp_1400f_16.get_m31(7);
                *row[110] = combination_limb_7_col110;
                let combination_limb_8_col111 = combination_tmp_1400f_16.get_m31(8);
                *row[111] = combination_limb_8_col111;
                let combination_limb_9_col112 = combination_tmp_1400f_16.get_m31(9);
                *row[112] = combination_limb_9_col112;
                let biased_limb_accumulator_u32_tmp_1400f_17 = PackedUInt32::from_m31(
                    ((((((cube_252_output_limb_0_col32) - (cube_252_output_limb_0_col42))
                        + (cube_252_output_limb_0_col52))
                        + (poseidon_round_keys_output_limb_10_col72))
                        - (combination_limb_0_col103))
                        + (M31_268435458)),
                );
                let p_coef_col113 =
                    ((biased_limb_accumulator_u32_tmp_1400f_17.low().as_m31()) - (M31_2));
                *row[113] = p_coef_col113;
                let carry_0_tmp_1400f_18 = (((((((cube_252_output_limb_0_col32)
                    - (cube_252_output_limb_0_col42))
                    + (cube_252_output_limb_0_col52))
                    + (poseidon_round_keys_output_limb_10_col72))
                    - (combination_limb_0_col103))
                    - (p_coef_col113))
                    * (M31_16));
                let carry_1_tmp_1400f_19 = (((((((carry_0_tmp_1400f_18)
                    + (cube_252_output_limb_1_col33))
                    - (cube_252_output_limb_1_col43))
                    + (cube_252_output_limb_1_col53))
                    + (poseidon_round_keys_output_limb_11_col73))
                    - (combination_limb_1_col104))
                    * (M31_16));
                let carry_2_tmp_1400f_20 = (((((((carry_1_tmp_1400f_19)
                    + (cube_252_output_limb_2_col34))
                    - (cube_252_output_limb_2_col44))
                    + (cube_252_output_limb_2_col54))
                    + (poseidon_round_keys_output_limb_12_col74))
                    - (combination_limb_2_col105))
                    * (M31_16));
                let carry_3_tmp_1400f_21 = (((((((carry_2_tmp_1400f_20)
                    + (cube_252_output_limb_3_col35))
                    - (cube_252_output_limb_3_col45))
                    + (cube_252_output_limb_3_col55))
                    + (poseidon_round_keys_output_limb_13_col75))
                    - (combination_limb_3_col106))
                    * (M31_16));
                let carry_4_tmp_1400f_22 = (((((((carry_3_tmp_1400f_21)
                    + (cube_252_output_limb_4_col36))
                    - (cube_252_output_limb_4_col46))
                    + (cube_252_output_limb_4_col56))
                    + (poseidon_round_keys_output_limb_14_col76))
                    - (combination_limb_4_col107))
                    * (M31_16));
                let carry_5_tmp_1400f_23 = (((((((carry_4_tmp_1400f_22)
                    + (cube_252_output_limb_5_col37))
                    - (cube_252_output_limb_5_col47))
                    + (cube_252_output_limb_5_col57))
                    + (poseidon_round_keys_output_limb_15_col77))
                    - (combination_limb_5_col108))
                    * (M31_16));
                let carry_6_tmp_1400f_24 = (((((((carry_5_tmp_1400f_23)
                    + (cube_252_output_limb_6_col38))
                    - (cube_252_output_limb_6_col48))
                    + (cube_252_output_limb_6_col58))
                    + (poseidon_round_keys_output_limb_16_col78))
                    - (combination_limb_6_col109))
                    * (M31_16));
                let carry_7_tmp_1400f_25 = ((((((((carry_6_tmp_1400f_24)
                    + (cube_252_output_limb_7_col39))
                    - (cube_252_output_limb_7_col49))
                    + (cube_252_output_limb_7_col59))
                    + (poseidon_round_keys_output_limb_17_col79))
                    - (combination_limb_7_col110))
                    - ((p_coef_col113) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_1400f_26 = (((((((carry_7_tmp_1400f_25)
                    + (cube_252_output_limb_8_col40))
                    - (cube_252_output_limb_8_col50))
                    + (cube_252_output_limb_8_col60))
                    + (poseidon_round_keys_output_limb_18_col80))
                    - (combination_limb_8_col111))
                    * (M31_16));
                *sub_component_inputs.range_check_3_3_3_3_3[2] = [
                    ((p_coef_col113) + (M31_2)),
                    ((carry_0_tmp_1400f_18) + (M31_2)),
                    ((carry_1_tmp_1400f_19) + (M31_2)),
                    ((carry_2_tmp_1400f_20) + (M31_2)),
                    ((carry_3_tmp_1400f_21) + (M31_2)),
                ];
                *lookup_data.range_check_3_3_3_3_3_6 = [
                    M31_502259093,
                    ((p_coef_col113) + (M31_2)),
                    ((carry_0_tmp_1400f_18) + (M31_2)),
                    ((carry_1_tmp_1400f_19) + (M31_2)),
                    ((carry_2_tmp_1400f_20) + (M31_2)),
                    ((carry_3_tmp_1400f_21) + (M31_2)),
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[3] = [
                    ((carry_4_tmp_1400f_22) + (M31_2)),
                    ((carry_5_tmp_1400f_23) + (M31_2)),
                    ((carry_6_tmp_1400f_24) + (M31_2)),
                    ((carry_7_tmp_1400f_25) + (M31_2)),
                    ((carry_8_tmp_1400f_26) + (M31_2)),
                ];
                *lookup_data.range_check_3_3_3_3_3_7 = [
                    M31_502259093,
                    ((carry_4_tmp_1400f_22) + (M31_2)),
                    ((carry_5_tmp_1400f_23) + (M31_2)),
                    ((carry_6_tmp_1400f_24) + (M31_2)),
                    ((carry_7_tmp_1400f_25) + (M31_2)),
                    ((carry_8_tmp_1400f_26) + (M31_2)),
                ];
                let linear_combination_n_4_coefs_1_m1_1_1_output_tmp_1400f_27 =
                    combination_tmp_1400f_16;

                // Linear Combination N 4 Coefs 1 1 M 2 1.

                let combination_tmp_1400f_28 = PackedFelt252Width27::from_packed_felt252(
                    (((((Felt252_0_0_0_0)
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_0,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_1,
                            ))))
                        - ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_1400f_2,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_1400f_3[2],
                            )))),
                );
                let combination_limb_0_col114 = combination_tmp_1400f_28.get_m31(0);
                *row[114] = combination_limb_0_col114;
                let combination_limb_1_col115 = combination_tmp_1400f_28.get_m31(1);
                *row[115] = combination_limb_1_col115;
                let combination_limb_2_col116 = combination_tmp_1400f_28.get_m31(2);
                *row[116] = combination_limb_2_col116;
                let combination_limb_3_col117 = combination_tmp_1400f_28.get_m31(3);
                *row[117] = combination_limb_3_col117;
                let combination_limb_4_col118 = combination_tmp_1400f_28.get_m31(4);
                *row[118] = combination_limb_4_col118;
                let combination_limb_5_col119 = combination_tmp_1400f_28.get_m31(5);
                *row[119] = combination_limb_5_col119;
                let combination_limb_6_col120 = combination_tmp_1400f_28.get_m31(6);
                *row[120] = combination_limb_6_col120;
                let combination_limb_7_col121 = combination_tmp_1400f_28.get_m31(7);
                *row[121] = combination_limb_7_col121;
                let combination_limb_8_col122 = combination_tmp_1400f_28.get_m31(8);
                *row[122] = combination_limb_8_col122;
                let combination_limb_9_col123 = combination_tmp_1400f_28.get_m31(9);
                *row[123] = combination_limb_9_col123;
                let biased_limb_accumulator_u32_tmp_1400f_29 = PackedUInt32::from_m31(
                    ((((((cube_252_output_limb_0_col32) + (cube_252_output_limb_0_col42))
                        - ((M31_2) * (cube_252_output_limb_0_col52)))
                        + (poseidon_round_keys_output_limb_20_col82))
                        - (combination_limb_0_col114))
                        + (M31_402653187)),
                );
                let p_coef_col124 =
                    ((biased_limb_accumulator_u32_tmp_1400f_29.low().as_m31()) - (M31_3));
                *row[124] = p_coef_col124;
                let carry_0_tmp_1400f_30 = (((((((cube_252_output_limb_0_col32)
                    + (cube_252_output_limb_0_col42))
                    - ((M31_2) * (cube_252_output_limb_0_col52)))
                    + (poseidon_round_keys_output_limb_20_col82))
                    - (combination_limb_0_col114))
                    - (p_coef_col124))
                    * (M31_16));
                let carry_1_tmp_1400f_31 = (((((((carry_0_tmp_1400f_30)
                    + (cube_252_output_limb_1_col33))
                    + (cube_252_output_limb_1_col43))
                    - ((M31_2) * (cube_252_output_limb_1_col53)))
                    + (poseidon_round_keys_output_limb_21_col83))
                    - (combination_limb_1_col115))
                    * (M31_16));
                let carry_2_tmp_1400f_32 = (((((((carry_1_tmp_1400f_31)
                    + (cube_252_output_limb_2_col34))
                    + (cube_252_output_limb_2_col44))
                    - ((M31_2) * (cube_252_output_limb_2_col54)))
                    + (poseidon_round_keys_output_limb_22_col84))
                    - (combination_limb_2_col116))
                    * (M31_16));
                let carry_3_tmp_1400f_33 = (((((((carry_2_tmp_1400f_32)
                    + (cube_252_output_limb_3_col35))
                    + (cube_252_output_limb_3_col45))
                    - ((M31_2) * (cube_252_output_limb_3_col55)))
                    + (poseidon_round_keys_output_limb_23_col85))
                    - (combination_limb_3_col117))
                    * (M31_16));
                let carry_4_tmp_1400f_34 = (((((((carry_3_tmp_1400f_33)
                    + (cube_252_output_limb_4_col36))
                    + (cube_252_output_limb_4_col46))
                    - ((M31_2) * (cube_252_output_limb_4_col56)))
                    + (poseidon_round_keys_output_limb_24_col86))
                    - (combination_limb_4_col118))
                    * (M31_16));
                let carry_5_tmp_1400f_35 = (((((((carry_4_tmp_1400f_34)
                    + (cube_252_output_limb_5_col37))
                    + (cube_252_output_limb_5_col47))
                    - ((M31_2) * (cube_252_output_limb_5_col57)))
                    + (poseidon_round_keys_output_limb_25_col87))
                    - (combination_limb_5_col119))
                    * (M31_16));
                let carry_6_tmp_1400f_36 = (((((((carry_5_tmp_1400f_35)
                    + (cube_252_output_limb_6_col38))
                    + (cube_252_output_limb_6_col48))
                    - ((M31_2) * (cube_252_output_limb_6_col58)))
                    + (poseidon_round_keys_output_limb_26_col88))
                    - (combination_limb_6_col120))
                    * (M31_16));
                let carry_7_tmp_1400f_37 = ((((((((carry_6_tmp_1400f_36)
                    + (cube_252_output_limb_7_col39))
                    + (cube_252_output_limb_7_col49))
                    - ((M31_2) * (cube_252_output_limb_7_col59)))
                    + (poseidon_round_keys_output_limb_27_col89))
                    - (combination_limb_7_col121))
                    - ((p_coef_col124) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_1400f_38 = (((((((carry_7_tmp_1400f_37)
                    + (cube_252_output_limb_8_col40))
                    + (cube_252_output_limb_8_col50))
                    - ((M31_2) * (cube_252_output_limb_8_col60)))
                    + (poseidon_round_keys_output_limb_28_col90))
                    - (combination_limb_8_col122))
                    * (M31_16));
                *sub_component_inputs.range_check_3_3_3_3_3[4] = [
                    ((p_coef_col124) + (M31_3)),
                    ((carry_0_tmp_1400f_30) + (M31_3)),
                    ((carry_1_tmp_1400f_31) + (M31_3)),
                    ((carry_2_tmp_1400f_32) + (M31_3)),
                    ((carry_3_tmp_1400f_33) + (M31_3)),
                ];
                *lookup_data.range_check_3_3_3_3_3_8 = [
                    M31_502259093,
                    ((p_coef_col124) + (M31_3)),
                    ((carry_0_tmp_1400f_30) + (M31_3)),
                    ((carry_1_tmp_1400f_31) + (M31_3)),
                    ((carry_2_tmp_1400f_32) + (M31_3)),
                    ((carry_3_tmp_1400f_33) + (M31_3)),
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[5] = [
                    ((carry_4_tmp_1400f_34) + (M31_3)),
                    ((carry_5_tmp_1400f_35) + (M31_3)),
                    ((carry_6_tmp_1400f_36) + (M31_3)),
                    ((carry_7_tmp_1400f_37) + (M31_3)),
                    ((carry_8_tmp_1400f_38) + (M31_3)),
                ];
                *lookup_data.range_check_3_3_3_3_3_9 = [
                    M31_502259093,
                    ((carry_4_tmp_1400f_34) + (M31_3)),
                    ((carry_5_tmp_1400f_35) + (M31_3)),
                    ((carry_6_tmp_1400f_36) + (M31_3)),
                    ((carry_7_tmp_1400f_37) + (M31_3)),
                    ((carry_8_tmp_1400f_38) + (M31_3)),
                ];
                let linear_combination_n_4_coefs_1_1_m2_1_output_tmp_1400f_39 =
                    combination_tmp_1400f_28;

                let enabler_col125 = enabler_col.packed_at(row_index);
                *row[125] = enabler_col125;
                *lookup_data.poseidon_full_round_chain_10 = [
                    M31_1480369132,
                    input_limb_0_col0,
                    input_limb_1_col1,
                    input_limb_2_col2,
                    input_limb_3_col3,
                    input_limb_4_col4,
                    input_limb_5_col5,
                    input_limb_6_col6,
                    input_limb_7_col7,
                    input_limb_8_col8,
                    input_limb_9_col9,
                    input_limb_10_col10,
                    input_limb_11_col11,
                    input_limb_12_col12,
                    input_limb_13_col13,
                    input_limb_14_col14,
                    input_limb_15_col15,
                    input_limb_16_col16,
                    input_limb_17_col17,
                    input_limb_18_col18,
                    input_limb_19_col19,
                    input_limb_20_col20,
                    input_limb_21_col21,
                    input_limb_22_col22,
                    input_limb_23_col23,
                    input_limb_24_col24,
                    input_limb_25_col25,
                    input_limb_26_col26,
                    input_limb_27_col27,
                    input_limb_28_col28,
                    input_limb_29_col29,
                    input_limb_30_col30,
                    input_limb_31_col31,
                ];
                *lookup_data.poseidon_full_round_chain_11 = [
                    M31_1480369132,
                    input_limb_0_col0,
                    ((input_limb_1_col1) + (M31_1)),
                    combination_limb_0_col92,
                    combination_limb_1_col93,
                    combination_limb_2_col94,
                    combination_limb_3_col95,
                    combination_limb_4_col96,
                    combination_limb_5_col97,
                    combination_limb_6_col98,
                    combination_limb_7_col99,
                    combination_limb_8_col100,
                    combination_limb_9_col101,
                    combination_limb_0_col103,
                    combination_limb_1_col104,
                    combination_limb_2_col105,
                    combination_limb_3_col106,
                    combination_limb_4_col107,
                    combination_limb_5_col108,
                    combination_limb_6_col109,
                    combination_limb_7_col110,
                    combination_limb_8_col111,
                    combination_limb_9_col112,
                    combination_limb_0_col114,
                    combination_limb_1_col115,
                    combination_limb_2_col116,
                    combination_limb_3_col117,
                    combination_limb_4_col118,
                    combination_limb_5_col119,
                    combination_limb_6_col120,
                    combination_limb_7_col121,
                    combination_limb_8_col122,
                    combination_limb_9_col123,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col125;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `poseidon_full_round_chain` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     cube_252_0[21] 0..20
//     cube_252_1[21] 21..41
//     cube_252_2[21] 42..62
//     poseidon_round_keys_3[32] 63..94
//     range_check_3_3_3_3_3_4[6] 95..100
//     range_check_3_3_3_3_3_5[6] 101..106
//     range_check_3_3_3_3_3_6[6] 107..112
//     range_check_3_3_3_3_3_7[6] 113..118
//     range_check_3_3_3_3_3_8[6] 119..124
//     range_check_3_3_3_3_3_9[6] 125..130
//     poseidon_full_round_chain_10[33] 131..163
//     poseidon_full_round_chain_11[33] 164..196
//     mults_0 197
//     mults_1 198
//     (199 words)
//   SUB-INPUT words:
//     cube_252[0] 0..9
//     cube_252[1] 10..19
//     cube_252[2] 20..29
//     poseidon_round_keys[0] 30
//     range_check_3_3_3_3_3[0] 31..35
//     range_check_3_3_3_3_3[1] 36..40
//     range_check_3_3_3_3_3[2] 41..45
//     range_check_3_3_3_3_3[3] 46..50
//     range_check_3_3_3_3_3[4] 51..55
//     range_check_3_3_3_3_3[5] 56..60
//     (61 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 199;
pub(crate) const N_SUB_INPUT_WORDS: usize = 61;

/// The per-row `poseidon_full_round_chain` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn poseidon_full_round_chain_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_16 = eval.m31_const(16);
    let m31_136 = eval.m31_const(136);
    let m31_512 = eval.m31_const(512);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217729 = eval.m31_const(134217729);
    let m31_268435458 = eval.m31_const(268435458);
    let m31_402653187 = eval.m31_const(402653187);
    let m31_502259093 = eval.m31_const(502259093);
    let m31_1024310512 = eval.m31_const(1024310512);
    let m31_1480369132 = eval.m31_const(1480369132);
    let m31_1987997202 = eval.m31_const(1987997202);
    let input_limb_0_col0 = eval.input(0);
    eval.set_col(0, input_limb_0_col0);
    let input_limb_1_col1 = eval.input(1);
    eval.set_col(1, input_limb_1_col1);
    let wg_v0 = eval.input(2);
    let wg_v1 = eval.input(3);
    let wg_v2 = eval.input(4);
    let wg_v3 = eval.input(5);
    let wg_v4 = eval.input(6);
    let wg_v5 = eval.input(7);
    let wg_v6 = eval.input(8);
    let wg_v7 = eval.input(9);
    let wg_v8 = eval.input(10);
    let wg_v9 = eval.input(11);
    let wg_v10 = [
        wg_v0, wg_v1, wg_v2, wg_v3, wg_v4, wg_v5, wg_v6, wg_v7, wg_v8, wg_v9,
    ];
    let input_limb_2_col2 = wg_v10[0];
    eval.set_col(2, input_limb_2_col2);
    let wg_v11 = eval.input(2);
    let wg_v12 = eval.input(3);
    let wg_v13 = eval.input(4);
    let wg_v14 = eval.input(5);
    let wg_v15 = eval.input(6);
    let wg_v16 = eval.input(7);
    let wg_v17 = eval.input(8);
    let wg_v18 = eval.input(9);
    let wg_v19 = eval.input(10);
    let wg_v20 = eval.input(11);
    let wg_v21 = [
        wg_v11, wg_v12, wg_v13, wg_v14, wg_v15, wg_v16, wg_v17, wg_v18, wg_v19, wg_v20,
    ];
    let input_limb_3_col3 = wg_v21[1];
    eval.set_col(3, input_limb_3_col3);
    let wg_v22 = eval.input(2);
    let wg_v23 = eval.input(3);
    let wg_v24 = eval.input(4);
    let wg_v25 = eval.input(5);
    let wg_v26 = eval.input(6);
    let wg_v27 = eval.input(7);
    let wg_v28 = eval.input(8);
    let wg_v29 = eval.input(9);
    let wg_v30 = eval.input(10);
    let wg_v31 = eval.input(11);
    let wg_v32 = [
        wg_v22, wg_v23, wg_v24, wg_v25, wg_v26, wg_v27, wg_v28, wg_v29, wg_v30, wg_v31,
    ];
    let input_limb_4_col4 = wg_v32[2];
    eval.set_col(4, input_limb_4_col4);
    let wg_v33 = eval.input(2);
    let wg_v34 = eval.input(3);
    let wg_v35 = eval.input(4);
    let wg_v36 = eval.input(5);
    let wg_v37 = eval.input(6);
    let wg_v38 = eval.input(7);
    let wg_v39 = eval.input(8);
    let wg_v40 = eval.input(9);
    let wg_v41 = eval.input(10);
    let wg_v42 = eval.input(11);
    let wg_v43 = [
        wg_v33, wg_v34, wg_v35, wg_v36, wg_v37, wg_v38, wg_v39, wg_v40, wg_v41, wg_v42,
    ];
    let input_limb_5_col5 = wg_v43[3];
    eval.set_col(5, input_limb_5_col5);
    let wg_v44 = eval.input(2);
    let wg_v45 = eval.input(3);
    let wg_v46 = eval.input(4);
    let wg_v47 = eval.input(5);
    let wg_v48 = eval.input(6);
    let wg_v49 = eval.input(7);
    let wg_v50 = eval.input(8);
    let wg_v51 = eval.input(9);
    let wg_v52 = eval.input(10);
    let wg_v53 = eval.input(11);
    let wg_v54 = [
        wg_v44, wg_v45, wg_v46, wg_v47, wg_v48, wg_v49, wg_v50, wg_v51, wg_v52, wg_v53,
    ];
    let input_limb_6_col6 = wg_v54[4];
    eval.set_col(6, input_limb_6_col6);
    let wg_v55 = eval.input(2);
    let wg_v56 = eval.input(3);
    let wg_v57 = eval.input(4);
    let wg_v58 = eval.input(5);
    let wg_v59 = eval.input(6);
    let wg_v60 = eval.input(7);
    let wg_v61 = eval.input(8);
    let wg_v62 = eval.input(9);
    let wg_v63 = eval.input(10);
    let wg_v64 = eval.input(11);
    let wg_v65 = [
        wg_v55, wg_v56, wg_v57, wg_v58, wg_v59, wg_v60, wg_v61, wg_v62, wg_v63, wg_v64,
    ];
    let input_limb_7_col7 = wg_v65[5];
    eval.set_col(7, input_limb_7_col7);
    let wg_v66 = eval.input(2);
    let wg_v67 = eval.input(3);
    let wg_v68 = eval.input(4);
    let wg_v69 = eval.input(5);
    let wg_v70 = eval.input(6);
    let wg_v71 = eval.input(7);
    let wg_v72 = eval.input(8);
    let wg_v73 = eval.input(9);
    let wg_v74 = eval.input(10);
    let wg_v75 = eval.input(11);
    let wg_v76 = [
        wg_v66, wg_v67, wg_v68, wg_v69, wg_v70, wg_v71, wg_v72, wg_v73, wg_v74, wg_v75,
    ];
    let input_limb_8_col8 = wg_v76[6];
    eval.set_col(8, input_limb_8_col8);
    let wg_v77 = eval.input(2);
    let wg_v78 = eval.input(3);
    let wg_v79 = eval.input(4);
    let wg_v80 = eval.input(5);
    let wg_v81 = eval.input(6);
    let wg_v82 = eval.input(7);
    let wg_v83 = eval.input(8);
    let wg_v84 = eval.input(9);
    let wg_v85 = eval.input(10);
    let wg_v86 = eval.input(11);
    let wg_v87 = [
        wg_v77, wg_v78, wg_v79, wg_v80, wg_v81, wg_v82, wg_v83, wg_v84, wg_v85, wg_v86,
    ];
    let input_limb_9_col9 = wg_v87[7];
    eval.set_col(9, input_limb_9_col9);
    let wg_v88 = eval.input(2);
    let wg_v89 = eval.input(3);
    let wg_v90 = eval.input(4);
    let wg_v91 = eval.input(5);
    let wg_v92 = eval.input(6);
    let wg_v93 = eval.input(7);
    let wg_v94 = eval.input(8);
    let wg_v95 = eval.input(9);
    let wg_v96 = eval.input(10);
    let wg_v97 = eval.input(11);
    let wg_v98 = [
        wg_v88, wg_v89, wg_v90, wg_v91, wg_v92, wg_v93, wg_v94, wg_v95, wg_v96, wg_v97,
    ];
    let input_limb_10_col10 = wg_v98[8];
    eval.set_col(10, input_limb_10_col10);
    let wg_v99 = eval.input(2);
    let wg_v100 = eval.input(3);
    let wg_v101 = eval.input(4);
    let wg_v102 = eval.input(5);
    let wg_v103 = eval.input(6);
    let wg_v104 = eval.input(7);
    let wg_v105 = eval.input(8);
    let wg_v106 = eval.input(9);
    let wg_v107 = eval.input(10);
    let wg_v108 = eval.input(11);
    let wg_v109 = [
        wg_v99, wg_v100, wg_v101, wg_v102, wg_v103, wg_v104, wg_v105, wg_v106, wg_v107, wg_v108,
    ];
    let input_limb_11_col11 = wg_v109[9];
    eval.set_col(11, input_limb_11_col11);
    let wg_v110 = eval.input(12);
    let wg_v111 = eval.input(13);
    let wg_v112 = eval.input(14);
    let wg_v113 = eval.input(15);
    let wg_v114 = eval.input(16);
    let wg_v115 = eval.input(17);
    let wg_v116 = eval.input(18);
    let wg_v117 = eval.input(19);
    let wg_v118 = eval.input(20);
    let wg_v119 = eval.input(21);
    let wg_v120 = [
        wg_v110, wg_v111, wg_v112, wg_v113, wg_v114, wg_v115, wg_v116, wg_v117, wg_v118, wg_v119,
    ];
    let input_limb_12_col12 = wg_v120[0];
    eval.set_col(12, input_limb_12_col12);
    let wg_v121 = eval.input(12);
    let wg_v122 = eval.input(13);
    let wg_v123 = eval.input(14);
    let wg_v124 = eval.input(15);
    let wg_v125 = eval.input(16);
    let wg_v126 = eval.input(17);
    let wg_v127 = eval.input(18);
    let wg_v128 = eval.input(19);
    let wg_v129 = eval.input(20);
    let wg_v130 = eval.input(21);
    let wg_v131 = [
        wg_v121, wg_v122, wg_v123, wg_v124, wg_v125, wg_v126, wg_v127, wg_v128, wg_v129, wg_v130,
    ];
    let input_limb_13_col13 = wg_v131[1];
    eval.set_col(13, input_limb_13_col13);
    let wg_v132 = eval.input(12);
    let wg_v133 = eval.input(13);
    let wg_v134 = eval.input(14);
    let wg_v135 = eval.input(15);
    let wg_v136 = eval.input(16);
    let wg_v137 = eval.input(17);
    let wg_v138 = eval.input(18);
    let wg_v139 = eval.input(19);
    let wg_v140 = eval.input(20);
    let wg_v141 = eval.input(21);
    let wg_v142 = [
        wg_v132, wg_v133, wg_v134, wg_v135, wg_v136, wg_v137, wg_v138, wg_v139, wg_v140, wg_v141,
    ];
    let input_limb_14_col14 = wg_v142[2];
    eval.set_col(14, input_limb_14_col14);
    let wg_v143 = eval.input(12);
    let wg_v144 = eval.input(13);
    let wg_v145 = eval.input(14);
    let wg_v146 = eval.input(15);
    let wg_v147 = eval.input(16);
    let wg_v148 = eval.input(17);
    let wg_v149 = eval.input(18);
    let wg_v150 = eval.input(19);
    let wg_v151 = eval.input(20);
    let wg_v152 = eval.input(21);
    let wg_v153 = [
        wg_v143, wg_v144, wg_v145, wg_v146, wg_v147, wg_v148, wg_v149, wg_v150, wg_v151, wg_v152,
    ];
    let input_limb_15_col15 = wg_v153[3];
    eval.set_col(15, input_limb_15_col15);
    let wg_v154 = eval.input(12);
    let wg_v155 = eval.input(13);
    let wg_v156 = eval.input(14);
    let wg_v157 = eval.input(15);
    let wg_v158 = eval.input(16);
    let wg_v159 = eval.input(17);
    let wg_v160 = eval.input(18);
    let wg_v161 = eval.input(19);
    let wg_v162 = eval.input(20);
    let wg_v163 = eval.input(21);
    let wg_v164 = [
        wg_v154, wg_v155, wg_v156, wg_v157, wg_v158, wg_v159, wg_v160, wg_v161, wg_v162, wg_v163,
    ];
    let input_limb_16_col16 = wg_v164[4];
    eval.set_col(16, input_limb_16_col16);
    let wg_v165 = eval.input(12);
    let wg_v166 = eval.input(13);
    let wg_v167 = eval.input(14);
    let wg_v168 = eval.input(15);
    let wg_v169 = eval.input(16);
    let wg_v170 = eval.input(17);
    let wg_v171 = eval.input(18);
    let wg_v172 = eval.input(19);
    let wg_v173 = eval.input(20);
    let wg_v174 = eval.input(21);
    let wg_v175 = [
        wg_v165, wg_v166, wg_v167, wg_v168, wg_v169, wg_v170, wg_v171, wg_v172, wg_v173, wg_v174,
    ];
    let input_limb_17_col17 = wg_v175[5];
    eval.set_col(17, input_limb_17_col17);
    let wg_v176 = eval.input(12);
    let wg_v177 = eval.input(13);
    let wg_v178 = eval.input(14);
    let wg_v179 = eval.input(15);
    let wg_v180 = eval.input(16);
    let wg_v181 = eval.input(17);
    let wg_v182 = eval.input(18);
    let wg_v183 = eval.input(19);
    let wg_v184 = eval.input(20);
    let wg_v185 = eval.input(21);
    let wg_v186 = [
        wg_v176, wg_v177, wg_v178, wg_v179, wg_v180, wg_v181, wg_v182, wg_v183, wg_v184, wg_v185,
    ];
    let input_limb_18_col18 = wg_v186[6];
    eval.set_col(18, input_limb_18_col18);
    let wg_v187 = eval.input(12);
    let wg_v188 = eval.input(13);
    let wg_v189 = eval.input(14);
    let wg_v190 = eval.input(15);
    let wg_v191 = eval.input(16);
    let wg_v192 = eval.input(17);
    let wg_v193 = eval.input(18);
    let wg_v194 = eval.input(19);
    let wg_v195 = eval.input(20);
    let wg_v196 = eval.input(21);
    let wg_v197 = [
        wg_v187, wg_v188, wg_v189, wg_v190, wg_v191, wg_v192, wg_v193, wg_v194, wg_v195, wg_v196,
    ];
    let input_limb_19_col19 = wg_v197[7];
    eval.set_col(19, input_limb_19_col19);
    let wg_v198 = eval.input(12);
    let wg_v199 = eval.input(13);
    let wg_v200 = eval.input(14);
    let wg_v201 = eval.input(15);
    let wg_v202 = eval.input(16);
    let wg_v203 = eval.input(17);
    let wg_v204 = eval.input(18);
    let wg_v205 = eval.input(19);
    let wg_v206 = eval.input(20);
    let wg_v207 = eval.input(21);
    let wg_v208 = [
        wg_v198, wg_v199, wg_v200, wg_v201, wg_v202, wg_v203, wg_v204, wg_v205, wg_v206, wg_v207,
    ];
    let input_limb_20_col20 = wg_v208[8];
    eval.set_col(20, input_limb_20_col20);
    let wg_v209 = eval.input(12);
    let wg_v210 = eval.input(13);
    let wg_v211 = eval.input(14);
    let wg_v212 = eval.input(15);
    let wg_v213 = eval.input(16);
    let wg_v214 = eval.input(17);
    let wg_v215 = eval.input(18);
    let wg_v216 = eval.input(19);
    let wg_v217 = eval.input(20);
    let wg_v218 = eval.input(21);
    let wg_v219 = [
        wg_v209, wg_v210, wg_v211, wg_v212, wg_v213, wg_v214, wg_v215, wg_v216, wg_v217, wg_v218,
    ];
    let input_limb_21_col21 = wg_v219[9];
    eval.set_col(21, input_limb_21_col21);
    let wg_v220 = eval.input(22);
    let wg_v221 = eval.input(23);
    let wg_v222 = eval.input(24);
    let wg_v223 = eval.input(25);
    let wg_v224 = eval.input(26);
    let wg_v225 = eval.input(27);
    let wg_v226 = eval.input(28);
    let wg_v227 = eval.input(29);
    let wg_v228 = eval.input(30);
    let wg_v229 = eval.input(31);
    let wg_v230 = [
        wg_v220, wg_v221, wg_v222, wg_v223, wg_v224, wg_v225, wg_v226, wg_v227, wg_v228, wg_v229,
    ];
    let input_limb_22_col22 = wg_v230[0];
    eval.set_col(22, input_limb_22_col22);
    let wg_v231 = eval.input(22);
    let wg_v232 = eval.input(23);
    let wg_v233 = eval.input(24);
    let wg_v234 = eval.input(25);
    let wg_v235 = eval.input(26);
    let wg_v236 = eval.input(27);
    let wg_v237 = eval.input(28);
    let wg_v238 = eval.input(29);
    let wg_v239 = eval.input(30);
    let wg_v240 = eval.input(31);
    let wg_v241 = [
        wg_v231, wg_v232, wg_v233, wg_v234, wg_v235, wg_v236, wg_v237, wg_v238, wg_v239, wg_v240,
    ];
    let input_limb_23_col23 = wg_v241[1];
    eval.set_col(23, input_limb_23_col23);
    let wg_v242 = eval.input(22);
    let wg_v243 = eval.input(23);
    let wg_v244 = eval.input(24);
    let wg_v245 = eval.input(25);
    let wg_v246 = eval.input(26);
    let wg_v247 = eval.input(27);
    let wg_v248 = eval.input(28);
    let wg_v249 = eval.input(29);
    let wg_v250 = eval.input(30);
    let wg_v251 = eval.input(31);
    let wg_v252 = [
        wg_v242, wg_v243, wg_v244, wg_v245, wg_v246, wg_v247, wg_v248, wg_v249, wg_v250, wg_v251,
    ];
    let input_limb_24_col24 = wg_v252[2];
    eval.set_col(24, input_limb_24_col24);
    let wg_v253 = eval.input(22);
    let wg_v254 = eval.input(23);
    let wg_v255 = eval.input(24);
    let wg_v256 = eval.input(25);
    let wg_v257 = eval.input(26);
    let wg_v258 = eval.input(27);
    let wg_v259 = eval.input(28);
    let wg_v260 = eval.input(29);
    let wg_v261 = eval.input(30);
    let wg_v262 = eval.input(31);
    let wg_v263 = [
        wg_v253, wg_v254, wg_v255, wg_v256, wg_v257, wg_v258, wg_v259, wg_v260, wg_v261, wg_v262,
    ];
    let input_limb_25_col25 = wg_v263[3];
    eval.set_col(25, input_limb_25_col25);
    let wg_v264 = eval.input(22);
    let wg_v265 = eval.input(23);
    let wg_v266 = eval.input(24);
    let wg_v267 = eval.input(25);
    let wg_v268 = eval.input(26);
    let wg_v269 = eval.input(27);
    let wg_v270 = eval.input(28);
    let wg_v271 = eval.input(29);
    let wg_v272 = eval.input(30);
    let wg_v273 = eval.input(31);
    let wg_v274 = [
        wg_v264, wg_v265, wg_v266, wg_v267, wg_v268, wg_v269, wg_v270, wg_v271, wg_v272, wg_v273,
    ];
    let input_limb_26_col26 = wg_v274[4];
    eval.set_col(26, input_limb_26_col26);
    let wg_v275 = eval.input(22);
    let wg_v276 = eval.input(23);
    let wg_v277 = eval.input(24);
    let wg_v278 = eval.input(25);
    let wg_v279 = eval.input(26);
    let wg_v280 = eval.input(27);
    let wg_v281 = eval.input(28);
    let wg_v282 = eval.input(29);
    let wg_v283 = eval.input(30);
    let wg_v284 = eval.input(31);
    let wg_v285 = [
        wg_v275, wg_v276, wg_v277, wg_v278, wg_v279, wg_v280, wg_v281, wg_v282, wg_v283, wg_v284,
    ];
    let input_limb_27_col27 = wg_v285[5];
    eval.set_col(27, input_limb_27_col27);
    let wg_v286 = eval.input(22);
    let wg_v287 = eval.input(23);
    let wg_v288 = eval.input(24);
    let wg_v289 = eval.input(25);
    let wg_v290 = eval.input(26);
    let wg_v291 = eval.input(27);
    let wg_v292 = eval.input(28);
    let wg_v293 = eval.input(29);
    let wg_v294 = eval.input(30);
    let wg_v295 = eval.input(31);
    let wg_v296 = [
        wg_v286, wg_v287, wg_v288, wg_v289, wg_v290, wg_v291, wg_v292, wg_v293, wg_v294, wg_v295,
    ];
    let input_limb_28_col28 = wg_v296[6];
    eval.set_col(28, input_limb_28_col28);
    let wg_v297 = eval.input(22);
    let wg_v298 = eval.input(23);
    let wg_v299 = eval.input(24);
    let wg_v300 = eval.input(25);
    let wg_v301 = eval.input(26);
    let wg_v302 = eval.input(27);
    let wg_v303 = eval.input(28);
    let wg_v304 = eval.input(29);
    let wg_v305 = eval.input(30);
    let wg_v306 = eval.input(31);
    let wg_v307 = [
        wg_v297, wg_v298, wg_v299, wg_v300, wg_v301, wg_v302, wg_v303, wg_v304, wg_v305, wg_v306,
    ];
    let input_limb_29_col29 = wg_v307[7];
    eval.set_col(29, input_limb_29_col29);
    let wg_v308 = eval.input(22);
    let wg_v309 = eval.input(23);
    let wg_v310 = eval.input(24);
    let wg_v311 = eval.input(25);
    let wg_v312 = eval.input(26);
    let wg_v313 = eval.input(27);
    let wg_v314 = eval.input(28);
    let wg_v315 = eval.input(29);
    let wg_v316 = eval.input(30);
    let wg_v317 = eval.input(31);
    let wg_v318 = [
        wg_v308, wg_v309, wg_v310, wg_v311, wg_v312, wg_v313, wg_v314, wg_v315, wg_v316, wg_v317,
    ];
    let input_limb_30_col30 = wg_v318[8];
    eval.set_col(30, input_limb_30_col30);
    let wg_v319 = eval.input(22);
    let wg_v320 = eval.input(23);
    let wg_v321 = eval.input(24);
    let wg_v322 = eval.input(25);
    let wg_v323 = eval.input(26);
    let wg_v324 = eval.input(27);
    let wg_v325 = eval.input(28);
    let wg_v326 = eval.input(29);
    let wg_v327 = eval.input(30);
    let wg_v328 = eval.input(31);
    let wg_v329 = [
        wg_v319, wg_v320, wg_v321, wg_v322, wg_v323, wg_v324, wg_v325, wg_v326, wg_v327, wg_v328,
    ];
    let input_limb_31_col31 = wg_v329[9];
    eval.set_col(31, input_limb_31_col31);
    let wg_v330 = eval.input(2);
    let wg_v331 = eval.input(3);
    let wg_v332 = eval.input(4);
    let wg_v333 = eval.input(5);
    let wg_v334 = eval.input(6);
    let wg_v335 = eval.input(7);
    let wg_v336 = eval.input(8);
    let wg_v337 = eval.input(9);
    let wg_v338 = eval.input(10);
    let wg_v339 = eval.input(11);
    let wg_v340 = [
        wg_v330, wg_v331, wg_v332, wg_v333, wg_v334, wg_v335, wg_v336, wg_v337, wg_v338, wg_v339,
    ];
    let wg_v341 = wg_v340;
    let wg_v342 = wg_v341[0];
    let wg_v343 = wg_v341[1];
    let wg_v344 = wg_v341[2];
    let wg_v345 = wg_v341[3];
    let wg_v346 = wg_v341[4];
    let wg_v347 = wg_v341[5];
    let wg_v348 = wg_v341[6];
    let wg_v349 = wg_v341[7];
    let wg_v350 = wg_v341[8];
    let wg_v351 = wg_v341[9];
    eval.set_sub_input_word(0, wg_v342);
    eval.set_sub_input_word(1, wg_v343);
    eval.set_sub_input_word(2, wg_v344);
    eval.set_sub_input_word(3, wg_v345);
    eval.set_sub_input_word(4, wg_v346);
    eval.set_sub_input_word(5, wg_v347);
    eval.set_sub_input_word(6, wg_v348);
    eval.set_sub_input_word(7, wg_v349);
    eval.set_sub_input_word(8, wg_v350);
    eval.set_sub_input_word(9, wg_v351);
    let wg_v352 = eval.input(2);
    let wg_v353 = eval.input(3);
    let wg_v354 = eval.input(4);
    let wg_v355 = eval.input(5);
    let wg_v356 = eval.input(6);
    let wg_v357 = eval.input(7);
    let wg_v358 = eval.input(8);
    let wg_v359 = eval.input(9);
    let wg_v360 = eval.input(10);
    let wg_v361 = eval.input(11);
    let wg_v362 = [
        wg_v352, wg_v353, wg_v354, wg_v355, wg_v356, wg_v357, wg_v358, wg_v359, wg_v360, wg_v361,
    ];
    let cube_252_output_tmp_1400f_0 = eval.deduce_cube_252(wg_v362);
    let cube_252_output_limb_0_col32 = cube_252_output_tmp_1400f_0[0];
    eval.set_col(32, cube_252_output_limb_0_col32);
    let cube_252_output_limb_1_col33 = cube_252_output_tmp_1400f_0[1];
    eval.set_col(33, cube_252_output_limb_1_col33);
    let cube_252_output_limb_2_col34 = cube_252_output_tmp_1400f_0[2];
    eval.set_col(34, cube_252_output_limb_2_col34);
    let cube_252_output_limb_3_col35 = cube_252_output_tmp_1400f_0[3];
    eval.set_col(35, cube_252_output_limb_3_col35);
    let cube_252_output_limb_4_col36 = cube_252_output_tmp_1400f_0[4];
    eval.set_col(36, cube_252_output_limb_4_col36);
    let cube_252_output_limb_5_col37 = cube_252_output_tmp_1400f_0[5];
    eval.set_col(37, cube_252_output_limb_5_col37);
    let cube_252_output_limb_6_col38 = cube_252_output_tmp_1400f_0[6];
    eval.set_col(38, cube_252_output_limb_6_col38);
    let cube_252_output_limb_7_col39 = cube_252_output_tmp_1400f_0[7];
    eval.set_col(39, cube_252_output_limb_7_col39);
    let cube_252_output_limb_8_col40 = cube_252_output_tmp_1400f_0[8];
    eval.set_col(40, cube_252_output_limb_8_col40);
    let cube_252_output_limb_9_col41 = cube_252_output_tmp_1400f_0[9];
    eval.set_col(41, cube_252_output_limb_9_col41);
    eval.set_lookup_word(0, m31_1987997202);
    eval.set_lookup_word(1, input_limb_2_col2);
    eval.set_lookup_word(2, input_limb_3_col3);
    eval.set_lookup_word(3, input_limb_4_col4);
    eval.set_lookup_word(4, input_limb_5_col5);
    eval.set_lookup_word(5, input_limb_6_col6);
    eval.set_lookup_word(6, input_limb_7_col7);
    eval.set_lookup_word(7, input_limb_8_col8);
    eval.set_lookup_word(8, input_limb_9_col9);
    eval.set_lookup_word(9, input_limb_10_col10);
    eval.set_lookup_word(10, input_limb_11_col11);
    eval.set_lookup_word(11, cube_252_output_limb_0_col32);
    eval.set_lookup_word(12, cube_252_output_limb_1_col33);
    eval.set_lookup_word(13, cube_252_output_limb_2_col34);
    eval.set_lookup_word(14, cube_252_output_limb_3_col35);
    eval.set_lookup_word(15, cube_252_output_limb_4_col36);
    eval.set_lookup_word(16, cube_252_output_limb_5_col37);
    eval.set_lookup_word(17, cube_252_output_limb_6_col38);
    eval.set_lookup_word(18, cube_252_output_limb_7_col39);
    eval.set_lookup_word(19, cube_252_output_limb_8_col40);
    eval.set_lookup_word(20, cube_252_output_limb_9_col41);
    let wg_v363 = eval.input(12);
    let wg_v364 = eval.input(13);
    let wg_v365 = eval.input(14);
    let wg_v366 = eval.input(15);
    let wg_v367 = eval.input(16);
    let wg_v368 = eval.input(17);
    let wg_v369 = eval.input(18);
    let wg_v370 = eval.input(19);
    let wg_v371 = eval.input(20);
    let wg_v372 = eval.input(21);
    let wg_v373 = [
        wg_v363, wg_v364, wg_v365, wg_v366, wg_v367, wg_v368, wg_v369, wg_v370, wg_v371, wg_v372,
    ];
    let wg_v374 = wg_v373;
    let wg_v375 = wg_v374[0];
    let wg_v376 = wg_v374[1];
    let wg_v377 = wg_v374[2];
    let wg_v378 = wg_v374[3];
    let wg_v379 = wg_v374[4];
    let wg_v380 = wg_v374[5];
    let wg_v381 = wg_v374[6];
    let wg_v382 = wg_v374[7];
    let wg_v383 = wg_v374[8];
    let wg_v384 = wg_v374[9];
    eval.set_sub_input_word(10, wg_v375);
    eval.set_sub_input_word(11, wg_v376);
    eval.set_sub_input_word(12, wg_v377);
    eval.set_sub_input_word(13, wg_v378);
    eval.set_sub_input_word(14, wg_v379);
    eval.set_sub_input_word(15, wg_v380);
    eval.set_sub_input_word(16, wg_v381);
    eval.set_sub_input_word(17, wg_v382);
    eval.set_sub_input_word(18, wg_v383);
    eval.set_sub_input_word(19, wg_v384);
    let wg_v385 = eval.input(12);
    let wg_v386 = eval.input(13);
    let wg_v387 = eval.input(14);
    let wg_v388 = eval.input(15);
    let wg_v389 = eval.input(16);
    let wg_v390 = eval.input(17);
    let wg_v391 = eval.input(18);
    let wg_v392 = eval.input(19);
    let wg_v393 = eval.input(20);
    let wg_v394 = eval.input(21);
    let wg_v395 = [
        wg_v385, wg_v386, wg_v387, wg_v388, wg_v389, wg_v390, wg_v391, wg_v392, wg_v393, wg_v394,
    ];
    let cube_252_output_tmp_1400f_1 = eval.deduce_cube_252(wg_v395);
    let cube_252_output_limb_0_col42 = cube_252_output_tmp_1400f_1[0];
    eval.set_col(42, cube_252_output_limb_0_col42);
    let cube_252_output_limb_1_col43 = cube_252_output_tmp_1400f_1[1];
    eval.set_col(43, cube_252_output_limb_1_col43);
    let cube_252_output_limb_2_col44 = cube_252_output_tmp_1400f_1[2];
    eval.set_col(44, cube_252_output_limb_2_col44);
    let cube_252_output_limb_3_col45 = cube_252_output_tmp_1400f_1[3];
    eval.set_col(45, cube_252_output_limb_3_col45);
    let cube_252_output_limb_4_col46 = cube_252_output_tmp_1400f_1[4];
    eval.set_col(46, cube_252_output_limb_4_col46);
    let cube_252_output_limb_5_col47 = cube_252_output_tmp_1400f_1[5];
    eval.set_col(47, cube_252_output_limb_5_col47);
    let cube_252_output_limb_6_col48 = cube_252_output_tmp_1400f_1[6];
    eval.set_col(48, cube_252_output_limb_6_col48);
    let cube_252_output_limb_7_col49 = cube_252_output_tmp_1400f_1[7];
    eval.set_col(49, cube_252_output_limb_7_col49);
    let cube_252_output_limb_8_col50 = cube_252_output_tmp_1400f_1[8];
    eval.set_col(50, cube_252_output_limb_8_col50);
    let cube_252_output_limb_9_col51 = cube_252_output_tmp_1400f_1[9];
    eval.set_col(51, cube_252_output_limb_9_col51);
    eval.set_lookup_word(21, m31_1987997202);
    eval.set_lookup_word(22, input_limb_12_col12);
    eval.set_lookup_word(23, input_limb_13_col13);
    eval.set_lookup_word(24, input_limb_14_col14);
    eval.set_lookup_word(25, input_limb_15_col15);
    eval.set_lookup_word(26, input_limb_16_col16);
    eval.set_lookup_word(27, input_limb_17_col17);
    eval.set_lookup_word(28, input_limb_18_col18);
    eval.set_lookup_word(29, input_limb_19_col19);
    eval.set_lookup_word(30, input_limb_20_col20);
    eval.set_lookup_word(31, input_limb_21_col21);
    eval.set_lookup_word(32, cube_252_output_limb_0_col42);
    eval.set_lookup_word(33, cube_252_output_limb_1_col43);
    eval.set_lookup_word(34, cube_252_output_limb_2_col44);
    eval.set_lookup_word(35, cube_252_output_limb_3_col45);
    eval.set_lookup_word(36, cube_252_output_limb_4_col46);
    eval.set_lookup_word(37, cube_252_output_limb_5_col47);
    eval.set_lookup_word(38, cube_252_output_limb_6_col48);
    eval.set_lookup_word(39, cube_252_output_limb_7_col49);
    eval.set_lookup_word(40, cube_252_output_limb_8_col50);
    eval.set_lookup_word(41, cube_252_output_limb_9_col51);
    let wg_v396 = eval.input(22);
    let wg_v397 = eval.input(23);
    let wg_v398 = eval.input(24);
    let wg_v399 = eval.input(25);
    let wg_v400 = eval.input(26);
    let wg_v401 = eval.input(27);
    let wg_v402 = eval.input(28);
    let wg_v403 = eval.input(29);
    let wg_v404 = eval.input(30);
    let wg_v405 = eval.input(31);
    let wg_v406 = [
        wg_v396, wg_v397, wg_v398, wg_v399, wg_v400, wg_v401, wg_v402, wg_v403, wg_v404, wg_v405,
    ];
    let wg_v407 = wg_v406;
    let wg_v408 = wg_v407[0];
    let wg_v409 = wg_v407[1];
    let wg_v410 = wg_v407[2];
    let wg_v411 = wg_v407[3];
    let wg_v412 = wg_v407[4];
    let wg_v413 = wg_v407[5];
    let wg_v414 = wg_v407[6];
    let wg_v415 = wg_v407[7];
    let wg_v416 = wg_v407[8];
    let wg_v417 = wg_v407[9];
    eval.set_sub_input_word(20, wg_v408);
    eval.set_sub_input_word(21, wg_v409);
    eval.set_sub_input_word(22, wg_v410);
    eval.set_sub_input_word(23, wg_v411);
    eval.set_sub_input_word(24, wg_v412);
    eval.set_sub_input_word(25, wg_v413);
    eval.set_sub_input_word(26, wg_v414);
    eval.set_sub_input_word(27, wg_v415);
    eval.set_sub_input_word(28, wg_v416);
    eval.set_sub_input_word(29, wg_v417);
    let wg_v418 = eval.input(22);
    let wg_v419 = eval.input(23);
    let wg_v420 = eval.input(24);
    let wg_v421 = eval.input(25);
    let wg_v422 = eval.input(26);
    let wg_v423 = eval.input(27);
    let wg_v424 = eval.input(28);
    let wg_v425 = eval.input(29);
    let wg_v426 = eval.input(30);
    let wg_v427 = eval.input(31);
    let wg_v428 = [
        wg_v418, wg_v419, wg_v420, wg_v421, wg_v422, wg_v423, wg_v424, wg_v425, wg_v426, wg_v427,
    ];
    let cube_252_output_tmp_1400f_2 = eval.deduce_cube_252(wg_v428);
    let cube_252_output_limb_0_col52 = cube_252_output_tmp_1400f_2[0];
    eval.set_col(52, cube_252_output_limb_0_col52);
    let cube_252_output_limb_1_col53 = cube_252_output_tmp_1400f_2[1];
    eval.set_col(53, cube_252_output_limb_1_col53);
    let cube_252_output_limb_2_col54 = cube_252_output_tmp_1400f_2[2];
    eval.set_col(54, cube_252_output_limb_2_col54);
    let cube_252_output_limb_3_col55 = cube_252_output_tmp_1400f_2[3];
    eval.set_col(55, cube_252_output_limb_3_col55);
    let cube_252_output_limb_4_col56 = cube_252_output_tmp_1400f_2[4];
    eval.set_col(56, cube_252_output_limb_4_col56);
    let cube_252_output_limb_5_col57 = cube_252_output_tmp_1400f_2[5];
    eval.set_col(57, cube_252_output_limb_5_col57);
    let cube_252_output_limb_6_col58 = cube_252_output_tmp_1400f_2[6];
    eval.set_col(58, cube_252_output_limb_6_col58);
    let cube_252_output_limb_7_col59 = cube_252_output_tmp_1400f_2[7];
    eval.set_col(59, cube_252_output_limb_7_col59);
    let cube_252_output_limb_8_col60 = cube_252_output_tmp_1400f_2[8];
    eval.set_col(60, cube_252_output_limb_8_col60);
    let cube_252_output_limb_9_col61 = cube_252_output_tmp_1400f_2[9];
    eval.set_col(61, cube_252_output_limb_9_col61);
    eval.set_lookup_word(42, m31_1987997202);
    eval.set_lookup_word(43, input_limb_22_col22);
    eval.set_lookup_word(44, input_limb_23_col23);
    eval.set_lookup_word(45, input_limb_24_col24);
    eval.set_lookup_word(46, input_limb_25_col25);
    eval.set_lookup_word(47, input_limb_26_col26);
    eval.set_lookup_word(48, input_limb_27_col27);
    eval.set_lookup_word(49, input_limb_28_col28);
    eval.set_lookup_word(50, input_limb_29_col29);
    eval.set_lookup_word(51, input_limb_30_col30);
    eval.set_lookup_word(52, input_limb_31_col31);
    eval.set_lookup_word(53, cube_252_output_limb_0_col52);
    eval.set_lookup_word(54, cube_252_output_limb_1_col53);
    eval.set_lookup_word(55, cube_252_output_limb_2_col54);
    eval.set_lookup_word(56, cube_252_output_limb_3_col55);
    eval.set_lookup_word(57, cube_252_output_limb_4_col56);
    eval.set_lookup_word(58, cube_252_output_limb_5_col57);
    eval.set_lookup_word(59, cube_252_output_limb_6_col58);
    eval.set_lookup_word(60, cube_252_output_limb_7_col59);
    eval.set_lookup_word(61, cube_252_output_limb_8_col60);
    eval.set_lookup_word(62, cube_252_output_limb_9_col61);
    eval.set_sub_input_word(30, input_limb_1_col1);
    let poseidon_round_keys_output_tmp_1400f_3 = eval.deduce_poseidon_round_keys(input_limb_1_col1);
    let poseidon_round_keys_output_limb_0_col62 = poseidon_round_keys_output_tmp_1400f_3[0][0];
    eval.set_col(62, poseidon_round_keys_output_limb_0_col62);
    let poseidon_round_keys_output_limb_1_col63 = poseidon_round_keys_output_tmp_1400f_3[0][1];
    eval.set_col(63, poseidon_round_keys_output_limb_1_col63);
    let poseidon_round_keys_output_limb_2_col64 = poseidon_round_keys_output_tmp_1400f_3[0][2];
    eval.set_col(64, poseidon_round_keys_output_limb_2_col64);
    let poseidon_round_keys_output_limb_3_col65 = poseidon_round_keys_output_tmp_1400f_3[0][3];
    eval.set_col(65, poseidon_round_keys_output_limb_3_col65);
    let poseidon_round_keys_output_limb_4_col66 = poseidon_round_keys_output_tmp_1400f_3[0][4];
    eval.set_col(66, poseidon_round_keys_output_limb_4_col66);
    let poseidon_round_keys_output_limb_5_col67 = poseidon_round_keys_output_tmp_1400f_3[0][5];
    eval.set_col(67, poseidon_round_keys_output_limb_5_col67);
    let poseidon_round_keys_output_limb_6_col68 = poseidon_round_keys_output_tmp_1400f_3[0][6];
    eval.set_col(68, poseidon_round_keys_output_limb_6_col68);
    let poseidon_round_keys_output_limb_7_col69 = poseidon_round_keys_output_tmp_1400f_3[0][7];
    eval.set_col(69, poseidon_round_keys_output_limb_7_col69);
    let poseidon_round_keys_output_limb_8_col70 = poseidon_round_keys_output_tmp_1400f_3[0][8];
    eval.set_col(70, poseidon_round_keys_output_limb_8_col70);
    let poseidon_round_keys_output_limb_9_col71 = poseidon_round_keys_output_tmp_1400f_3[0][9];
    eval.set_col(71, poseidon_round_keys_output_limb_9_col71);
    let poseidon_round_keys_output_limb_10_col72 = poseidon_round_keys_output_tmp_1400f_3[1][0];
    eval.set_col(72, poseidon_round_keys_output_limb_10_col72);
    let poseidon_round_keys_output_limb_11_col73 = poseidon_round_keys_output_tmp_1400f_3[1][1];
    eval.set_col(73, poseidon_round_keys_output_limb_11_col73);
    let poseidon_round_keys_output_limb_12_col74 = poseidon_round_keys_output_tmp_1400f_3[1][2];
    eval.set_col(74, poseidon_round_keys_output_limb_12_col74);
    let poseidon_round_keys_output_limb_13_col75 = poseidon_round_keys_output_tmp_1400f_3[1][3];
    eval.set_col(75, poseidon_round_keys_output_limb_13_col75);
    let poseidon_round_keys_output_limb_14_col76 = poseidon_round_keys_output_tmp_1400f_3[1][4];
    eval.set_col(76, poseidon_round_keys_output_limb_14_col76);
    let poseidon_round_keys_output_limb_15_col77 = poseidon_round_keys_output_tmp_1400f_3[1][5];
    eval.set_col(77, poseidon_round_keys_output_limb_15_col77);
    let poseidon_round_keys_output_limb_16_col78 = poseidon_round_keys_output_tmp_1400f_3[1][6];
    eval.set_col(78, poseidon_round_keys_output_limb_16_col78);
    let poseidon_round_keys_output_limb_17_col79 = poseidon_round_keys_output_tmp_1400f_3[1][7];
    eval.set_col(79, poseidon_round_keys_output_limb_17_col79);
    let poseidon_round_keys_output_limb_18_col80 = poseidon_round_keys_output_tmp_1400f_3[1][8];
    eval.set_col(80, poseidon_round_keys_output_limb_18_col80);
    let poseidon_round_keys_output_limb_19_col81 = poseidon_round_keys_output_tmp_1400f_3[1][9];
    eval.set_col(81, poseidon_round_keys_output_limb_19_col81);
    let poseidon_round_keys_output_limb_20_col82 = poseidon_round_keys_output_tmp_1400f_3[2][0];
    eval.set_col(82, poseidon_round_keys_output_limb_20_col82);
    let poseidon_round_keys_output_limb_21_col83 = poseidon_round_keys_output_tmp_1400f_3[2][1];
    eval.set_col(83, poseidon_round_keys_output_limb_21_col83);
    let poseidon_round_keys_output_limb_22_col84 = poseidon_round_keys_output_tmp_1400f_3[2][2];
    eval.set_col(84, poseidon_round_keys_output_limb_22_col84);
    let poseidon_round_keys_output_limb_23_col85 = poseidon_round_keys_output_tmp_1400f_3[2][3];
    eval.set_col(85, poseidon_round_keys_output_limb_23_col85);
    let poseidon_round_keys_output_limb_24_col86 = poseidon_round_keys_output_tmp_1400f_3[2][4];
    eval.set_col(86, poseidon_round_keys_output_limb_24_col86);
    let poseidon_round_keys_output_limb_25_col87 = poseidon_round_keys_output_tmp_1400f_3[2][5];
    eval.set_col(87, poseidon_round_keys_output_limb_25_col87);
    let poseidon_round_keys_output_limb_26_col88 = poseidon_round_keys_output_tmp_1400f_3[2][6];
    eval.set_col(88, poseidon_round_keys_output_limb_26_col88);
    let poseidon_round_keys_output_limb_27_col89 = poseidon_round_keys_output_tmp_1400f_3[2][7];
    eval.set_col(89, poseidon_round_keys_output_limb_27_col89);
    let poseidon_round_keys_output_limb_28_col90 = poseidon_round_keys_output_tmp_1400f_3[2][8];
    eval.set_col(90, poseidon_round_keys_output_limb_28_col90);
    let poseidon_round_keys_output_limb_29_col91 = poseidon_round_keys_output_tmp_1400f_3[2][9];
    eval.set_col(91, poseidon_round_keys_output_limb_29_col91);
    eval.set_lookup_word(63, m31_1024310512);
    eval.set_lookup_word(64, input_limb_1_col1);
    eval.set_lookup_word(65, poseidon_round_keys_output_limb_0_col62);
    eval.set_lookup_word(66, poseidon_round_keys_output_limb_1_col63);
    eval.set_lookup_word(67, poseidon_round_keys_output_limb_2_col64);
    eval.set_lookup_word(68, poseidon_round_keys_output_limb_3_col65);
    eval.set_lookup_word(69, poseidon_round_keys_output_limb_4_col66);
    eval.set_lookup_word(70, poseidon_round_keys_output_limb_5_col67);
    eval.set_lookup_word(71, poseidon_round_keys_output_limb_6_col68);
    eval.set_lookup_word(72, poseidon_round_keys_output_limb_7_col69);
    eval.set_lookup_word(73, poseidon_round_keys_output_limb_8_col70);
    eval.set_lookup_word(74, poseidon_round_keys_output_limb_9_col71);
    eval.set_lookup_word(75, poseidon_round_keys_output_limb_10_col72);
    eval.set_lookup_word(76, poseidon_round_keys_output_limb_11_col73);
    eval.set_lookup_word(77, poseidon_round_keys_output_limb_12_col74);
    eval.set_lookup_word(78, poseidon_round_keys_output_limb_13_col75);
    eval.set_lookup_word(79, poseidon_round_keys_output_limb_14_col76);
    eval.set_lookup_word(80, poseidon_round_keys_output_limb_15_col77);
    eval.set_lookup_word(81, poseidon_round_keys_output_limb_16_col78);
    eval.set_lookup_word(82, poseidon_round_keys_output_limb_17_col79);
    eval.set_lookup_word(83, poseidon_round_keys_output_limb_18_col80);
    eval.set_lookup_word(84, poseidon_round_keys_output_limb_19_col81);
    eval.set_lookup_word(85, poseidon_round_keys_output_limb_20_col82);
    eval.set_lookup_word(86, poseidon_round_keys_output_limb_21_col83);
    eval.set_lookup_word(87, poseidon_round_keys_output_limb_22_col84);
    eval.set_lookup_word(88, poseidon_round_keys_output_limb_23_col85);
    eval.set_lookup_word(89, poseidon_round_keys_output_limb_24_col86);
    eval.set_lookup_word(90, poseidon_round_keys_output_limb_25_col87);
    eval.set_lookup_word(91, poseidon_round_keys_output_limb_26_col88);
    eval.set_lookup_word(92, poseidon_round_keys_output_limb_27_col89);
    eval.set_lookup_word(93, poseidon_round_keys_output_limb_28_col90);
    eval.set_lookup_word(94, poseidon_round_keys_output_limb_29_col91);
    let wg_v429 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v430 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v431 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_0);
    let wg_v432 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v433 = eval.felt_mul(wg_v432.clone(), wg_v431.clone());
    let wg_v434 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v435 = eval.felt_add(wg_v434.clone(), wg_v433.clone());
    let wg_v436 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v437 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_1);
    let wg_v438 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v439 = eval.felt_mul(wg_v438.clone(), wg_v437.clone());
    let wg_v440 = eval.felt_add(wg_v435.clone(), wg_v439.clone());
    let wg_v441 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v442 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_2);
    let wg_v443 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v444 = eval.felt_mul(wg_v443.clone(), wg_v442.clone());
    let wg_v445 = eval.felt_add(wg_v440.clone(), wg_v444.clone());
    let wg_v446 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v447 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_1400f_3[0]);
    let wg_v448 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v449 = eval.felt_mul(wg_v448.clone(), wg_v447.clone());
    let wg_v450 = eval.felt_add(wg_v445.clone(), wg_v449.clone());
    let wg_v451 = eval.felt_get_m31(&wg_v450, 0);
    let wg_v452 = eval.felt_get_m31(&wg_v450, 1);
    let wg_v453 = eval.m31_mul(wg_v452, m31_512);
    let wg_v454 = eval.m31_add(wg_v451, wg_v453);
    let wg_v455 = eval.felt_get_m31(&wg_v450, 2);
    let wg_v456 = eval.m31_mul(wg_v455, m31_262144);
    let wg_v457 = eval.m31_add(wg_v454, wg_v456);
    let wg_v458 = eval.felt_get_m31(&wg_v450, 3);
    let wg_v459 = eval.felt_get_m31(&wg_v450, 4);
    let wg_v460 = eval.m31_mul(wg_v459, m31_512);
    let wg_v461 = eval.m31_add(wg_v458, wg_v460);
    let wg_v462 = eval.felt_get_m31(&wg_v450, 5);
    let wg_v463 = eval.m31_mul(wg_v462, m31_262144);
    let wg_v464 = eval.m31_add(wg_v461, wg_v463);
    let wg_v465 = eval.felt_get_m31(&wg_v450, 6);
    let wg_v466 = eval.felt_get_m31(&wg_v450, 7);
    let wg_v467 = eval.m31_mul(wg_v466, m31_512);
    let wg_v468 = eval.m31_add(wg_v465, wg_v467);
    let wg_v469 = eval.felt_get_m31(&wg_v450, 8);
    let wg_v470 = eval.m31_mul(wg_v469, m31_262144);
    let wg_v471 = eval.m31_add(wg_v468, wg_v470);
    let wg_v472 = eval.felt_get_m31(&wg_v450, 9);
    let wg_v473 = eval.felt_get_m31(&wg_v450, 10);
    let wg_v474 = eval.m31_mul(wg_v473, m31_512);
    let wg_v475 = eval.m31_add(wg_v472, wg_v474);
    let wg_v476 = eval.felt_get_m31(&wg_v450, 11);
    let wg_v477 = eval.m31_mul(wg_v476, m31_262144);
    let wg_v478 = eval.m31_add(wg_v475, wg_v477);
    let wg_v479 = eval.felt_get_m31(&wg_v450, 12);
    let wg_v480 = eval.felt_get_m31(&wg_v450, 13);
    let wg_v481 = eval.m31_mul(wg_v480, m31_512);
    let wg_v482 = eval.m31_add(wg_v479, wg_v481);
    let wg_v483 = eval.felt_get_m31(&wg_v450, 14);
    let wg_v484 = eval.m31_mul(wg_v483, m31_262144);
    let wg_v485 = eval.m31_add(wg_v482, wg_v484);
    let wg_v486 = eval.felt_get_m31(&wg_v450, 15);
    let wg_v487 = eval.felt_get_m31(&wg_v450, 16);
    let wg_v488 = eval.m31_mul(wg_v487, m31_512);
    let wg_v489 = eval.m31_add(wg_v486, wg_v488);
    let wg_v490 = eval.felt_get_m31(&wg_v450, 17);
    let wg_v491 = eval.m31_mul(wg_v490, m31_262144);
    let wg_v492 = eval.m31_add(wg_v489, wg_v491);
    let wg_v493 = eval.felt_get_m31(&wg_v450, 18);
    let wg_v494 = eval.felt_get_m31(&wg_v450, 19);
    let wg_v495 = eval.m31_mul(wg_v494, m31_512);
    let wg_v496 = eval.m31_add(wg_v493, wg_v495);
    let wg_v497 = eval.felt_get_m31(&wg_v450, 20);
    let wg_v498 = eval.m31_mul(wg_v497, m31_262144);
    let wg_v499 = eval.m31_add(wg_v496, wg_v498);
    let wg_v500 = eval.felt_get_m31(&wg_v450, 21);
    let wg_v501 = eval.felt_get_m31(&wg_v450, 22);
    let wg_v502 = eval.m31_mul(wg_v501, m31_512);
    let wg_v503 = eval.m31_add(wg_v500, wg_v502);
    let wg_v504 = eval.felt_get_m31(&wg_v450, 23);
    let wg_v505 = eval.m31_mul(wg_v504, m31_262144);
    let wg_v506 = eval.m31_add(wg_v503, wg_v505);
    let wg_v507 = eval.felt_get_m31(&wg_v450, 24);
    let wg_v508 = eval.felt_get_m31(&wg_v450, 25);
    let wg_v509 = eval.m31_mul(wg_v508, m31_512);
    let wg_v510 = eval.m31_add(wg_v507, wg_v509);
    let wg_v511 = eval.felt_get_m31(&wg_v450, 26);
    let wg_v512 = eval.m31_mul(wg_v511, m31_262144);
    let wg_v513 = eval.m31_add(wg_v510, wg_v512);
    let wg_v514 = eval.felt_get_m31(&wg_v450, 27);
    let combination_tmp_1400f_4 = [
        wg_v457, wg_v464, wg_v471, wg_v478, wg_v485, wg_v492, wg_v499, wg_v506, wg_v513, wg_v514,
    ];
    let combination_limb_0_col92 = combination_tmp_1400f_4[0];
    eval.set_col(92, combination_limb_0_col92);
    let combination_limb_1_col93 = combination_tmp_1400f_4[1];
    eval.set_col(93, combination_limb_1_col93);
    let combination_limb_2_col94 = combination_tmp_1400f_4[2];
    eval.set_col(94, combination_limb_2_col94);
    let combination_limb_3_col95 = combination_tmp_1400f_4[3];
    eval.set_col(95, combination_limb_3_col95);
    let combination_limb_4_col96 = combination_tmp_1400f_4[4];
    eval.set_col(96, combination_limb_4_col96);
    let combination_limb_5_col97 = combination_tmp_1400f_4[5];
    eval.set_col(97, combination_limb_5_col97);
    let combination_limb_6_col98 = combination_tmp_1400f_4[6];
    eval.set_col(98, combination_limb_6_col98);
    let combination_limb_7_col99 = combination_tmp_1400f_4[7];
    eval.set_col(99, combination_limb_7_col99);
    let combination_limb_8_col100 = combination_tmp_1400f_4[8];
    eval.set_col(100, combination_limb_8_col100);
    let combination_limb_9_col101 = combination_tmp_1400f_4[9];
    eval.set_col(101, combination_limb_9_col101);
    let wg_v515 = eval.m31_mul(m31_3, cube_252_output_limb_0_col32);
    let wg_v516 = eval.m31_add(wg_v515, cube_252_output_limb_0_col42);
    let wg_v517 = eval.m31_add(wg_v516, cube_252_output_limb_0_col52);
    let wg_v518 = eval.m31_add(wg_v517, poseidon_round_keys_output_limb_0_col62);
    let wg_v519 = eval.m31_sub(wg_v518, combination_limb_0_col92);
    let wg_v520 = eval.m31_add(wg_v519, m31_134217729);
    let biased_limb_accumulator_u32_tmp_1400f_5 = eval.u32_from_m31(wg_v520);
    let wg_v521 = eval.u32_low(biased_limb_accumulator_u32_tmp_1400f_5);
    let wg_v522 = eval.u16_as_m31(wg_v521);
    let p_coef_col102 = eval.m31_sub(wg_v522, m31_1);
    eval.set_col(102, p_coef_col102);
    let wg_v523 = eval.m31_mul(m31_3, cube_252_output_limb_0_col32);
    let wg_v524 = eval.m31_add(wg_v523, cube_252_output_limb_0_col42);
    let wg_v525 = eval.m31_add(wg_v524, cube_252_output_limb_0_col52);
    let wg_v526 = eval.m31_add(wg_v525, poseidon_round_keys_output_limb_0_col62);
    let wg_v527 = eval.m31_sub(wg_v526, combination_limb_0_col92);
    let wg_v528 = eval.m31_sub(wg_v527, p_coef_col102);
    let carry_0_tmp_1400f_6 = eval.m31_mul(wg_v528, m31_16);
    let wg_v529 = eval.m31_mul(m31_3, cube_252_output_limb_1_col33);
    let wg_v530 = eval.m31_add(carry_0_tmp_1400f_6, wg_v529);
    let wg_v531 = eval.m31_add(wg_v530, cube_252_output_limb_1_col43);
    let wg_v532 = eval.m31_add(wg_v531, cube_252_output_limb_1_col53);
    let wg_v533 = eval.m31_add(wg_v532, poseidon_round_keys_output_limb_1_col63);
    let wg_v534 = eval.m31_sub(wg_v533, combination_limb_1_col93);
    let carry_1_tmp_1400f_7 = eval.m31_mul(wg_v534, m31_16);
    let wg_v535 = eval.m31_mul(m31_3, cube_252_output_limb_2_col34);
    let wg_v536 = eval.m31_add(carry_1_tmp_1400f_7, wg_v535);
    let wg_v537 = eval.m31_add(wg_v536, cube_252_output_limb_2_col44);
    let wg_v538 = eval.m31_add(wg_v537, cube_252_output_limb_2_col54);
    let wg_v539 = eval.m31_add(wg_v538, poseidon_round_keys_output_limb_2_col64);
    let wg_v540 = eval.m31_sub(wg_v539, combination_limb_2_col94);
    let carry_2_tmp_1400f_8 = eval.m31_mul(wg_v540, m31_16);
    let wg_v541 = eval.m31_mul(m31_3, cube_252_output_limb_3_col35);
    let wg_v542 = eval.m31_add(carry_2_tmp_1400f_8, wg_v541);
    let wg_v543 = eval.m31_add(wg_v542, cube_252_output_limb_3_col45);
    let wg_v544 = eval.m31_add(wg_v543, cube_252_output_limb_3_col55);
    let wg_v545 = eval.m31_add(wg_v544, poseidon_round_keys_output_limb_3_col65);
    let wg_v546 = eval.m31_sub(wg_v545, combination_limb_3_col95);
    let carry_3_tmp_1400f_9 = eval.m31_mul(wg_v546, m31_16);
    let wg_v547 = eval.m31_mul(m31_3, cube_252_output_limb_4_col36);
    let wg_v548 = eval.m31_add(carry_3_tmp_1400f_9, wg_v547);
    let wg_v549 = eval.m31_add(wg_v548, cube_252_output_limb_4_col46);
    let wg_v550 = eval.m31_add(wg_v549, cube_252_output_limb_4_col56);
    let wg_v551 = eval.m31_add(wg_v550, poseidon_round_keys_output_limb_4_col66);
    let wg_v552 = eval.m31_sub(wg_v551, combination_limb_4_col96);
    let carry_4_tmp_1400f_10 = eval.m31_mul(wg_v552, m31_16);
    let wg_v553 = eval.m31_mul(m31_3, cube_252_output_limb_5_col37);
    let wg_v554 = eval.m31_add(carry_4_tmp_1400f_10, wg_v553);
    let wg_v555 = eval.m31_add(wg_v554, cube_252_output_limb_5_col47);
    let wg_v556 = eval.m31_add(wg_v555, cube_252_output_limb_5_col57);
    let wg_v557 = eval.m31_add(wg_v556, poseidon_round_keys_output_limb_5_col67);
    let wg_v558 = eval.m31_sub(wg_v557, combination_limb_5_col97);
    let carry_5_tmp_1400f_11 = eval.m31_mul(wg_v558, m31_16);
    let wg_v559 = eval.m31_mul(m31_3, cube_252_output_limb_6_col38);
    let wg_v560 = eval.m31_add(carry_5_tmp_1400f_11, wg_v559);
    let wg_v561 = eval.m31_add(wg_v560, cube_252_output_limb_6_col48);
    let wg_v562 = eval.m31_add(wg_v561, cube_252_output_limb_6_col58);
    let wg_v563 = eval.m31_add(wg_v562, poseidon_round_keys_output_limb_6_col68);
    let wg_v564 = eval.m31_sub(wg_v563, combination_limb_6_col98);
    let carry_6_tmp_1400f_12 = eval.m31_mul(wg_v564, m31_16);
    let wg_v565 = eval.m31_mul(m31_3, cube_252_output_limb_7_col39);
    let wg_v566 = eval.m31_add(carry_6_tmp_1400f_12, wg_v565);
    let wg_v567 = eval.m31_add(wg_v566, cube_252_output_limb_7_col49);
    let wg_v568 = eval.m31_add(wg_v567, cube_252_output_limb_7_col59);
    let wg_v569 = eval.m31_add(wg_v568, poseidon_round_keys_output_limb_7_col69);
    let wg_v570 = eval.m31_sub(wg_v569, combination_limb_7_col99);
    let wg_v571 = eval.m31_mul(p_coef_col102, m31_136);
    let wg_v572 = eval.m31_sub(wg_v570, wg_v571);
    let carry_7_tmp_1400f_13 = eval.m31_mul(wg_v572, m31_16);
    let wg_v573 = eval.m31_mul(m31_3, cube_252_output_limb_8_col40);
    let wg_v574 = eval.m31_add(carry_7_tmp_1400f_13, wg_v573);
    let wg_v575 = eval.m31_add(wg_v574, cube_252_output_limb_8_col50);
    let wg_v576 = eval.m31_add(wg_v575, cube_252_output_limb_8_col60);
    let wg_v577 = eval.m31_add(wg_v576, poseidon_round_keys_output_limb_8_col70);
    let wg_v578 = eval.m31_sub(wg_v577, combination_limb_8_col100);
    let carry_8_tmp_1400f_14 = eval.m31_mul(wg_v578, m31_16);
    let wg_v579 = eval.m31_add(p_coef_col102, m31_1);
    let wg_v580 = eval.m31_add(carry_0_tmp_1400f_6, m31_1);
    let wg_v581 = eval.m31_add(carry_1_tmp_1400f_7, m31_1);
    let wg_v582 = eval.m31_add(carry_2_tmp_1400f_8, m31_1);
    let wg_v583 = eval.m31_add(carry_3_tmp_1400f_9, m31_1);
    eval.set_sub_input_word(31, wg_v579);
    eval.set_sub_input_word(32, wg_v580);
    eval.set_sub_input_word(33, wg_v581);
    eval.set_sub_input_word(34, wg_v582);
    eval.set_sub_input_word(35, wg_v583);
    eval.set_lookup_word(95, m31_502259093);
    let wg_v584 = eval.m31_add(p_coef_col102, m31_1);
    eval.set_lookup_word(96, wg_v584);
    let wg_v585 = eval.m31_add(carry_0_tmp_1400f_6, m31_1);
    eval.set_lookup_word(97, wg_v585);
    let wg_v586 = eval.m31_add(carry_1_tmp_1400f_7, m31_1);
    eval.set_lookup_word(98, wg_v586);
    let wg_v587 = eval.m31_add(carry_2_tmp_1400f_8, m31_1);
    eval.set_lookup_word(99, wg_v587);
    let wg_v588 = eval.m31_add(carry_3_tmp_1400f_9, m31_1);
    eval.set_lookup_word(100, wg_v588);
    let wg_v589 = eval.m31_add(carry_4_tmp_1400f_10, m31_1);
    let wg_v590 = eval.m31_add(carry_5_tmp_1400f_11, m31_1);
    let wg_v591 = eval.m31_add(carry_6_tmp_1400f_12, m31_1);
    let wg_v592 = eval.m31_add(carry_7_tmp_1400f_13, m31_1);
    let wg_v593 = eval.m31_add(carry_8_tmp_1400f_14, m31_1);
    eval.set_sub_input_word(36, wg_v589);
    eval.set_sub_input_word(37, wg_v590);
    eval.set_sub_input_word(38, wg_v591);
    eval.set_sub_input_word(39, wg_v592);
    eval.set_sub_input_word(40, wg_v593);
    eval.set_lookup_word(101, m31_502259093);
    let wg_v594 = eval.m31_add(carry_4_tmp_1400f_10, m31_1);
    eval.set_lookup_word(102, wg_v594);
    let wg_v595 = eval.m31_add(carry_5_tmp_1400f_11, m31_1);
    eval.set_lookup_word(103, wg_v595);
    let wg_v596 = eval.m31_add(carry_6_tmp_1400f_12, m31_1);
    eval.set_lookup_word(104, wg_v596);
    let wg_v597 = eval.m31_add(carry_7_tmp_1400f_13, m31_1);
    eval.set_lookup_word(105, wg_v597);
    let wg_v598 = eval.m31_add(carry_8_tmp_1400f_14, m31_1);
    eval.set_lookup_word(106, wg_v598);
    let linear_combination_n_4_coefs_3_1_1_1_output_tmp_1400f_15 = combination_tmp_1400f_4;
    let wg_v599 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v600 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v601 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_0);
    let wg_v602 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v603 = eval.felt_mul(wg_v602.clone(), wg_v601.clone());
    let wg_v604 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v605 = eval.felt_add(wg_v604.clone(), wg_v603.clone());
    let wg_v606 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v607 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_1);
    let wg_v608 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v609 = eval.felt_mul(wg_v608.clone(), wg_v607.clone());
    let wg_v610 = eval.felt_sub(wg_v605.clone(), wg_v609.clone());
    let wg_v611 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v612 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_2);
    let wg_v613 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v614 = eval.felt_mul(wg_v613.clone(), wg_v612.clone());
    let wg_v615 = eval.felt_add(wg_v610.clone(), wg_v614.clone());
    let wg_v616 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v617 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_1400f_3[1]);
    let wg_v618 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v619 = eval.felt_mul(wg_v618.clone(), wg_v617.clone());
    let wg_v620 = eval.felt_add(wg_v615.clone(), wg_v619.clone());
    let wg_v621 = eval.felt_get_m31(&wg_v620, 0);
    let wg_v622 = eval.felt_get_m31(&wg_v620, 1);
    let wg_v623 = eval.m31_mul(wg_v622, m31_512);
    let wg_v624 = eval.m31_add(wg_v621, wg_v623);
    let wg_v625 = eval.felt_get_m31(&wg_v620, 2);
    let wg_v626 = eval.m31_mul(wg_v625, m31_262144);
    let wg_v627 = eval.m31_add(wg_v624, wg_v626);
    let wg_v628 = eval.felt_get_m31(&wg_v620, 3);
    let wg_v629 = eval.felt_get_m31(&wg_v620, 4);
    let wg_v630 = eval.m31_mul(wg_v629, m31_512);
    let wg_v631 = eval.m31_add(wg_v628, wg_v630);
    let wg_v632 = eval.felt_get_m31(&wg_v620, 5);
    let wg_v633 = eval.m31_mul(wg_v632, m31_262144);
    let wg_v634 = eval.m31_add(wg_v631, wg_v633);
    let wg_v635 = eval.felt_get_m31(&wg_v620, 6);
    let wg_v636 = eval.felt_get_m31(&wg_v620, 7);
    let wg_v637 = eval.m31_mul(wg_v636, m31_512);
    let wg_v638 = eval.m31_add(wg_v635, wg_v637);
    let wg_v639 = eval.felt_get_m31(&wg_v620, 8);
    let wg_v640 = eval.m31_mul(wg_v639, m31_262144);
    let wg_v641 = eval.m31_add(wg_v638, wg_v640);
    let wg_v642 = eval.felt_get_m31(&wg_v620, 9);
    let wg_v643 = eval.felt_get_m31(&wg_v620, 10);
    let wg_v644 = eval.m31_mul(wg_v643, m31_512);
    let wg_v645 = eval.m31_add(wg_v642, wg_v644);
    let wg_v646 = eval.felt_get_m31(&wg_v620, 11);
    let wg_v647 = eval.m31_mul(wg_v646, m31_262144);
    let wg_v648 = eval.m31_add(wg_v645, wg_v647);
    let wg_v649 = eval.felt_get_m31(&wg_v620, 12);
    let wg_v650 = eval.felt_get_m31(&wg_v620, 13);
    let wg_v651 = eval.m31_mul(wg_v650, m31_512);
    let wg_v652 = eval.m31_add(wg_v649, wg_v651);
    let wg_v653 = eval.felt_get_m31(&wg_v620, 14);
    let wg_v654 = eval.m31_mul(wg_v653, m31_262144);
    let wg_v655 = eval.m31_add(wg_v652, wg_v654);
    let wg_v656 = eval.felt_get_m31(&wg_v620, 15);
    let wg_v657 = eval.felt_get_m31(&wg_v620, 16);
    let wg_v658 = eval.m31_mul(wg_v657, m31_512);
    let wg_v659 = eval.m31_add(wg_v656, wg_v658);
    let wg_v660 = eval.felt_get_m31(&wg_v620, 17);
    let wg_v661 = eval.m31_mul(wg_v660, m31_262144);
    let wg_v662 = eval.m31_add(wg_v659, wg_v661);
    let wg_v663 = eval.felt_get_m31(&wg_v620, 18);
    let wg_v664 = eval.felt_get_m31(&wg_v620, 19);
    let wg_v665 = eval.m31_mul(wg_v664, m31_512);
    let wg_v666 = eval.m31_add(wg_v663, wg_v665);
    let wg_v667 = eval.felt_get_m31(&wg_v620, 20);
    let wg_v668 = eval.m31_mul(wg_v667, m31_262144);
    let wg_v669 = eval.m31_add(wg_v666, wg_v668);
    let wg_v670 = eval.felt_get_m31(&wg_v620, 21);
    let wg_v671 = eval.felt_get_m31(&wg_v620, 22);
    let wg_v672 = eval.m31_mul(wg_v671, m31_512);
    let wg_v673 = eval.m31_add(wg_v670, wg_v672);
    let wg_v674 = eval.felt_get_m31(&wg_v620, 23);
    let wg_v675 = eval.m31_mul(wg_v674, m31_262144);
    let wg_v676 = eval.m31_add(wg_v673, wg_v675);
    let wg_v677 = eval.felt_get_m31(&wg_v620, 24);
    let wg_v678 = eval.felt_get_m31(&wg_v620, 25);
    let wg_v679 = eval.m31_mul(wg_v678, m31_512);
    let wg_v680 = eval.m31_add(wg_v677, wg_v679);
    let wg_v681 = eval.felt_get_m31(&wg_v620, 26);
    let wg_v682 = eval.m31_mul(wg_v681, m31_262144);
    let wg_v683 = eval.m31_add(wg_v680, wg_v682);
    let wg_v684 = eval.felt_get_m31(&wg_v620, 27);
    let combination_tmp_1400f_16 = [
        wg_v627, wg_v634, wg_v641, wg_v648, wg_v655, wg_v662, wg_v669, wg_v676, wg_v683, wg_v684,
    ];
    let combination_limb_0_col103 = combination_tmp_1400f_16[0];
    eval.set_col(103, combination_limb_0_col103);
    let combination_limb_1_col104 = combination_tmp_1400f_16[1];
    eval.set_col(104, combination_limb_1_col104);
    let combination_limb_2_col105 = combination_tmp_1400f_16[2];
    eval.set_col(105, combination_limb_2_col105);
    let combination_limb_3_col106 = combination_tmp_1400f_16[3];
    eval.set_col(106, combination_limb_3_col106);
    let combination_limb_4_col107 = combination_tmp_1400f_16[4];
    eval.set_col(107, combination_limb_4_col107);
    let combination_limb_5_col108 = combination_tmp_1400f_16[5];
    eval.set_col(108, combination_limb_5_col108);
    let combination_limb_6_col109 = combination_tmp_1400f_16[6];
    eval.set_col(109, combination_limb_6_col109);
    let combination_limb_7_col110 = combination_tmp_1400f_16[7];
    eval.set_col(110, combination_limb_7_col110);
    let combination_limb_8_col111 = combination_tmp_1400f_16[8];
    eval.set_col(111, combination_limb_8_col111);
    let combination_limb_9_col112 = combination_tmp_1400f_16[9];
    eval.set_col(112, combination_limb_9_col112);
    let wg_v685 = eval.m31_sub(cube_252_output_limb_0_col32, cube_252_output_limb_0_col42);
    let wg_v686 = eval.m31_add(wg_v685, cube_252_output_limb_0_col52);
    let wg_v687 = eval.m31_add(wg_v686, poseidon_round_keys_output_limb_10_col72);
    let wg_v688 = eval.m31_sub(wg_v687, combination_limb_0_col103);
    let wg_v689 = eval.m31_add(wg_v688, m31_268435458);
    let biased_limb_accumulator_u32_tmp_1400f_17 = eval.u32_from_m31(wg_v689);
    let wg_v690 = eval.u32_low(biased_limb_accumulator_u32_tmp_1400f_17);
    let wg_v691 = eval.u16_as_m31(wg_v690);
    let p_coef_col113 = eval.m31_sub(wg_v691, m31_2);
    eval.set_col(113, p_coef_col113);
    let wg_v692 = eval.m31_sub(cube_252_output_limb_0_col32, cube_252_output_limb_0_col42);
    let wg_v693 = eval.m31_add(wg_v692, cube_252_output_limb_0_col52);
    let wg_v694 = eval.m31_add(wg_v693, poseidon_round_keys_output_limb_10_col72);
    let wg_v695 = eval.m31_sub(wg_v694, combination_limb_0_col103);
    let wg_v696 = eval.m31_sub(wg_v695, p_coef_col113);
    let carry_0_tmp_1400f_18 = eval.m31_mul(wg_v696, m31_16);
    let wg_v697 = eval.m31_add(carry_0_tmp_1400f_18, cube_252_output_limb_1_col33);
    let wg_v698 = eval.m31_sub(wg_v697, cube_252_output_limb_1_col43);
    let wg_v699 = eval.m31_add(wg_v698, cube_252_output_limb_1_col53);
    let wg_v700 = eval.m31_add(wg_v699, poseidon_round_keys_output_limb_11_col73);
    let wg_v701 = eval.m31_sub(wg_v700, combination_limb_1_col104);
    let carry_1_tmp_1400f_19 = eval.m31_mul(wg_v701, m31_16);
    let wg_v702 = eval.m31_add(carry_1_tmp_1400f_19, cube_252_output_limb_2_col34);
    let wg_v703 = eval.m31_sub(wg_v702, cube_252_output_limb_2_col44);
    let wg_v704 = eval.m31_add(wg_v703, cube_252_output_limb_2_col54);
    let wg_v705 = eval.m31_add(wg_v704, poseidon_round_keys_output_limb_12_col74);
    let wg_v706 = eval.m31_sub(wg_v705, combination_limb_2_col105);
    let carry_2_tmp_1400f_20 = eval.m31_mul(wg_v706, m31_16);
    let wg_v707 = eval.m31_add(carry_2_tmp_1400f_20, cube_252_output_limb_3_col35);
    let wg_v708 = eval.m31_sub(wg_v707, cube_252_output_limb_3_col45);
    let wg_v709 = eval.m31_add(wg_v708, cube_252_output_limb_3_col55);
    let wg_v710 = eval.m31_add(wg_v709, poseidon_round_keys_output_limb_13_col75);
    let wg_v711 = eval.m31_sub(wg_v710, combination_limb_3_col106);
    let carry_3_tmp_1400f_21 = eval.m31_mul(wg_v711, m31_16);
    let wg_v712 = eval.m31_add(carry_3_tmp_1400f_21, cube_252_output_limb_4_col36);
    let wg_v713 = eval.m31_sub(wg_v712, cube_252_output_limb_4_col46);
    let wg_v714 = eval.m31_add(wg_v713, cube_252_output_limb_4_col56);
    let wg_v715 = eval.m31_add(wg_v714, poseidon_round_keys_output_limb_14_col76);
    let wg_v716 = eval.m31_sub(wg_v715, combination_limb_4_col107);
    let carry_4_tmp_1400f_22 = eval.m31_mul(wg_v716, m31_16);
    let wg_v717 = eval.m31_add(carry_4_tmp_1400f_22, cube_252_output_limb_5_col37);
    let wg_v718 = eval.m31_sub(wg_v717, cube_252_output_limb_5_col47);
    let wg_v719 = eval.m31_add(wg_v718, cube_252_output_limb_5_col57);
    let wg_v720 = eval.m31_add(wg_v719, poseidon_round_keys_output_limb_15_col77);
    let wg_v721 = eval.m31_sub(wg_v720, combination_limb_5_col108);
    let carry_5_tmp_1400f_23 = eval.m31_mul(wg_v721, m31_16);
    let wg_v722 = eval.m31_add(carry_5_tmp_1400f_23, cube_252_output_limb_6_col38);
    let wg_v723 = eval.m31_sub(wg_v722, cube_252_output_limb_6_col48);
    let wg_v724 = eval.m31_add(wg_v723, cube_252_output_limb_6_col58);
    let wg_v725 = eval.m31_add(wg_v724, poseidon_round_keys_output_limb_16_col78);
    let wg_v726 = eval.m31_sub(wg_v725, combination_limb_6_col109);
    let carry_6_tmp_1400f_24 = eval.m31_mul(wg_v726, m31_16);
    let wg_v727 = eval.m31_add(carry_6_tmp_1400f_24, cube_252_output_limb_7_col39);
    let wg_v728 = eval.m31_sub(wg_v727, cube_252_output_limb_7_col49);
    let wg_v729 = eval.m31_add(wg_v728, cube_252_output_limb_7_col59);
    let wg_v730 = eval.m31_add(wg_v729, poseidon_round_keys_output_limb_17_col79);
    let wg_v731 = eval.m31_sub(wg_v730, combination_limb_7_col110);
    let wg_v732 = eval.m31_mul(p_coef_col113, m31_136);
    let wg_v733 = eval.m31_sub(wg_v731, wg_v732);
    let carry_7_tmp_1400f_25 = eval.m31_mul(wg_v733, m31_16);
    let wg_v734 = eval.m31_add(carry_7_tmp_1400f_25, cube_252_output_limb_8_col40);
    let wg_v735 = eval.m31_sub(wg_v734, cube_252_output_limb_8_col50);
    let wg_v736 = eval.m31_add(wg_v735, cube_252_output_limb_8_col60);
    let wg_v737 = eval.m31_add(wg_v736, poseidon_round_keys_output_limb_18_col80);
    let wg_v738 = eval.m31_sub(wg_v737, combination_limb_8_col111);
    let carry_8_tmp_1400f_26 = eval.m31_mul(wg_v738, m31_16);
    let wg_v739 = eval.m31_add(p_coef_col113, m31_2);
    let wg_v740 = eval.m31_add(carry_0_tmp_1400f_18, m31_2);
    let wg_v741 = eval.m31_add(carry_1_tmp_1400f_19, m31_2);
    let wg_v742 = eval.m31_add(carry_2_tmp_1400f_20, m31_2);
    let wg_v743 = eval.m31_add(carry_3_tmp_1400f_21, m31_2);
    eval.set_sub_input_word(41, wg_v739);
    eval.set_sub_input_word(42, wg_v740);
    eval.set_sub_input_word(43, wg_v741);
    eval.set_sub_input_word(44, wg_v742);
    eval.set_sub_input_word(45, wg_v743);
    eval.set_lookup_word(107, m31_502259093);
    let wg_v744 = eval.m31_add(p_coef_col113, m31_2);
    eval.set_lookup_word(108, wg_v744);
    let wg_v745 = eval.m31_add(carry_0_tmp_1400f_18, m31_2);
    eval.set_lookup_word(109, wg_v745);
    let wg_v746 = eval.m31_add(carry_1_tmp_1400f_19, m31_2);
    eval.set_lookup_word(110, wg_v746);
    let wg_v747 = eval.m31_add(carry_2_tmp_1400f_20, m31_2);
    eval.set_lookup_word(111, wg_v747);
    let wg_v748 = eval.m31_add(carry_3_tmp_1400f_21, m31_2);
    eval.set_lookup_word(112, wg_v748);
    let wg_v749 = eval.m31_add(carry_4_tmp_1400f_22, m31_2);
    let wg_v750 = eval.m31_add(carry_5_tmp_1400f_23, m31_2);
    let wg_v751 = eval.m31_add(carry_6_tmp_1400f_24, m31_2);
    let wg_v752 = eval.m31_add(carry_7_tmp_1400f_25, m31_2);
    let wg_v753 = eval.m31_add(carry_8_tmp_1400f_26, m31_2);
    eval.set_sub_input_word(46, wg_v749);
    eval.set_sub_input_word(47, wg_v750);
    eval.set_sub_input_word(48, wg_v751);
    eval.set_sub_input_word(49, wg_v752);
    eval.set_sub_input_word(50, wg_v753);
    eval.set_lookup_word(113, m31_502259093);
    let wg_v754 = eval.m31_add(carry_4_tmp_1400f_22, m31_2);
    eval.set_lookup_word(114, wg_v754);
    let wg_v755 = eval.m31_add(carry_5_tmp_1400f_23, m31_2);
    eval.set_lookup_word(115, wg_v755);
    let wg_v756 = eval.m31_add(carry_6_tmp_1400f_24, m31_2);
    eval.set_lookup_word(116, wg_v756);
    let wg_v757 = eval.m31_add(carry_7_tmp_1400f_25, m31_2);
    eval.set_lookup_word(117, wg_v757);
    let wg_v758 = eval.m31_add(carry_8_tmp_1400f_26, m31_2);
    eval.set_lookup_word(118, wg_v758);
    let linear_combination_n_4_coefs_1_m1_1_1_output_tmp_1400f_27 = combination_tmp_1400f_16;
    let wg_v759 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v760 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v761 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_0);
    let wg_v762 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v763 = eval.felt_mul(wg_v762.clone(), wg_v761.clone());
    let wg_v764 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v765 = eval.felt_add(wg_v764.clone(), wg_v763.clone());
    let wg_v766 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v767 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_1);
    let wg_v768 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v769 = eval.felt_mul(wg_v768.clone(), wg_v767.clone());
    let wg_v770 = eval.felt_add(wg_v765.clone(), wg_v769.clone());
    let wg_v771 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v772 = eval.felt_from_w27_words(cube_252_output_tmp_1400f_2);
    let wg_v773 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v774 = eval.felt_mul(wg_v773.clone(), wg_v772.clone());
    let wg_v775 = eval.felt_sub(wg_v770.clone(), wg_v774.clone());
    let wg_v776 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v777 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_1400f_3[2]);
    let wg_v778 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v779 = eval.felt_mul(wg_v778.clone(), wg_v777.clone());
    let wg_v780 = eval.felt_add(wg_v775.clone(), wg_v779.clone());
    let wg_v781 = eval.felt_get_m31(&wg_v780, 0);
    let wg_v782 = eval.felt_get_m31(&wg_v780, 1);
    let wg_v783 = eval.m31_mul(wg_v782, m31_512);
    let wg_v784 = eval.m31_add(wg_v781, wg_v783);
    let wg_v785 = eval.felt_get_m31(&wg_v780, 2);
    let wg_v786 = eval.m31_mul(wg_v785, m31_262144);
    let wg_v787 = eval.m31_add(wg_v784, wg_v786);
    let wg_v788 = eval.felt_get_m31(&wg_v780, 3);
    let wg_v789 = eval.felt_get_m31(&wg_v780, 4);
    let wg_v790 = eval.m31_mul(wg_v789, m31_512);
    let wg_v791 = eval.m31_add(wg_v788, wg_v790);
    let wg_v792 = eval.felt_get_m31(&wg_v780, 5);
    let wg_v793 = eval.m31_mul(wg_v792, m31_262144);
    let wg_v794 = eval.m31_add(wg_v791, wg_v793);
    let wg_v795 = eval.felt_get_m31(&wg_v780, 6);
    let wg_v796 = eval.felt_get_m31(&wg_v780, 7);
    let wg_v797 = eval.m31_mul(wg_v796, m31_512);
    let wg_v798 = eval.m31_add(wg_v795, wg_v797);
    let wg_v799 = eval.felt_get_m31(&wg_v780, 8);
    let wg_v800 = eval.m31_mul(wg_v799, m31_262144);
    let wg_v801 = eval.m31_add(wg_v798, wg_v800);
    let wg_v802 = eval.felt_get_m31(&wg_v780, 9);
    let wg_v803 = eval.felt_get_m31(&wg_v780, 10);
    let wg_v804 = eval.m31_mul(wg_v803, m31_512);
    let wg_v805 = eval.m31_add(wg_v802, wg_v804);
    let wg_v806 = eval.felt_get_m31(&wg_v780, 11);
    let wg_v807 = eval.m31_mul(wg_v806, m31_262144);
    let wg_v808 = eval.m31_add(wg_v805, wg_v807);
    let wg_v809 = eval.felt_get_m31(&wg_v780, 12);
    let wg_v810 = eval.felt_get_m31(&wg_v780, 13);
    let wg_v811 = eval.m31_mul(wg_v810, m31_512);
    let wg_v812 = eval.m31_add(wg_v809, wg_v811);
    let wg_v813 = eval.felt_get_m31(&wg_v780, 14);
    let wg_v814 = eval.m31_mul(wg_v813, m31_262144);
    let wg_v815 = eval.m31_add(wg_v812, wg_v814);
    let wg_v816 = eval.felt_get_m31(&wg_v780, 15);
    let wg_v817 = eval.felt_get_m31(&wg_v780, 16);
    let wg_v818 = eval.m31_mul(wg_v817, m31_512);
    let wg_v819 = eval.m31_add(wg_v816, wg_v818);
    let wg_v820 = eval.felt_get_m31(&wg_v780, 17);
    let wg_v821 = eval.m31_mul(wg_v820, m31_262144);
    let wg_v822 = eval.m31_add(wg_v819, wg_v821);
    let wg_v823 = eval.felt_get_m31(&wg_v780, 18);
    let wg_v824 = eval.felt_get_m31(&wg_v780, 19);
    let wg_v825 = eval.m31_mul(wg_v824, m31_512);
    let wg_v826 = eval.m31_add(wg_v823, wg_v825);
    let wg_v827 = eval.felt_get_m31(&wg_v780, 20);
    let wg_v828 = eval.m31_mul(wg_v827, m31_262144);
    let wg_v829 = eval.m31_add(wg_v826, wg_v828);
    let wg_v830 = eval.felt_get_m31(&wg_v780, 21);
    let wg_v831 = eval.felt_get_m31(&wg_v780, 22);
    let wg_v832 = eval.m31_mul(wg_v831, m31_512);
    let wg_v833 = eval.m31_add(wg_v830, wg_v832);
    let wg_v834 = eval.felt_get_m31(&wg_v780, 23);
    let wg_v835 = eval.m31_mul(wg_v834, m31_262144);
    let wg_v836 = eval.m31_add(wg_v833, wg_v835);
    let wg_v837 = eval.felt_get_m31(&wg_v780, 24);
    let wg_v838 = eval.felt_get_m31(&wg_v780, 25);
    let wg_v839 = eval.m31_mul(wg_v838, m31_512);
    let wg_v840 = eval.m31_add(wg_v837, wg_v839);
    let wg_v841 = eval.felt_get_m31(&wg_v780, 26);
    let wg_v842 = eval.m31_mul(wg_v841, m31_262144);
    let wg_v843 = eval.m31_add(wg_v840, wg_v842);
    let wg_v844 = eval.felt_get_m31(&wg_v780, 27);
    let combination_tmp_1400f_28 = [
        wg_v787, wg_v794, wg_v801, wg_v808, wg_v815, wg_v822, wg_v829, wg_v836, wg_v843, wg_v844,
    ];
    let combination_limb_0_col114 = combination_tmp_1400f_28[0];
    eval.set_col(114, combination_limb_0_col114);
    let combination_limb_1_col115 = combination_tmp_1400f_28[1];
    eval.set_col(115, combination_limb_1_col115);
    let combination_limb_2_col116 = combination_tmp_1400f_28[2];
    eval.set_col(116, combination_limb_2_col116);
    let combination_limb_3_col117 = combination_tmp_1400f_28[3];
    eval.set_col(117, combination_limb_3_col117);
    let combination_limb_4_col118 = combination_tmp_1400f_28[4];
    eval.set_col(118, combination_limb_4_col118);
    let combination_limb_5_col119 = combination_tmp_1400f_28[5];
    eval.set_col(119, combination_limb_5_col119);
    let combination_limb_6_col120 = combination_tmp_1400f_28[6];
    eval.set_col(120, combination_limb_6_col120);
    let combination_limb_7_col121 = combination_tmp_1400f_28[7];
    eval.set_col(121, combination_limb_7_col121);
    let combination_limb_8_col122 = combination_tmp_1400f_28[8];
    eval.set_col(122, combination_limb_8_col122);
    let combination_limb_9_col123 = combination_tmp_1400f_28[9];
    eval.set_col(123, combination_limb_9_col123);
    let wg_v845 = eval.m31_add(cube_252_output_limb_0_col32, cube_252_output_limb_0_col42);
    let wg_v846 = eval.m31_mul(m31_2, cube_252_output_limb_0_col52);
    let wg_v847 = eval.m31_sub(wg_v845, wg_v846);
    let wg_v848 = eval.m31_add(wg_v847, poseidon_round_keys_output_limb_20_col82);
    let wg_v849 = eval.m31_sub(wg_v848, combination_limb_0_col114);
    let wg_v850 = eval.m31_add(wg_v849, m31_402653187);
    let biased_limb_accumulator_u32_tmp_1400f_29 = eval.u32_from_m31(wg_v850);
    let wg_v851 = eval.u32_low(biased_limb_accumulator_u32_tmp_1400f_29);
    let wg_v852 = eval.u16_as_m31(wg_v851);
    let p_coef_col124 = eval.m31_sub(wg_v852, m31_3);
    eval.set_col(124, p_coef_col124);
    let wg_v853 = eval.m31_add(cube_252_output_limb_0_col32, cube_252_output_limb_0_col42);
    let wg_v854 = eval.m31_mul(m31_2, cube_252_output_limb_0_col52);
    let wg_v855 = eval.m31_sub(wg_v853, wg_v854);
    let wg_v856 = eval.m31_add(wg_v855, poseidon_round_keys_output_limb_20_col82);
    let wg_v857 = eval.m31_sub(wg_v856, combination_limb_0_col114);
    let wg_v858 = eval.m31_sub(wg_v857, p_coef_col124);
    let carry_0_tmp_1400f_30 = eval.m31_mul(wg_v858, m31_16);
    let wg_v859 = eval.m31_add(carry_0_tmp_1400f_30, cube_252_output_limb_1_col33);
    let wg_v860 = eval.m31_add(wg_v859, cube_252_output_limb_1_col43);
    let wg_v861 = eval.m31_mul(m31_2, cube_252_output_limb_1_col53);
    let wg_v862 = eval.m31_sub(wg_v860, wg_v861);
    let wg_v863 = eval.m31_add(wg_v862, poseidon_round_keys_output_limb_21_col83);
    let wg_v864 = eval.m31_sub(wg_v863, combination_limb_1_col115);
    let carry_1_tmp_1400f_31 = eval.m31_mul(wg_v864, m31_16);
    let wg_v865 = eval.m31_add(carry_1_tmp_1400f_31, cube_252_output_limb_2_col34);
    let wg_v866 = eval.m31_add(wg_v865, cube_252_output_limb_2_col44);
    let wg_v867 = eval.m31_mul(m31_2, cube_252_output_limb_2_col54);
    let wg_v868 = eval.m31_sub(wg_v866, wg_v867);
    let wg_v869 = eval.m31_add(wg_v868, poseidon_round_keys_output_limb_22_col84);
    let wg_v870 = eval.m31_sub(wg_v869, combination_limb_2_col116);
    let carry_2_tmp_1400f_32 = eval.m31_mul(wg_v870, m31_16);
    let wg_v871 = eval.m31_add(carry_2_tmp_1400f_32, cube_252_output_limb_3_col35);
    let wg_v872 = eval.m31_add(wg_v871, cube_252_output_limb_3_col45);
    let wg_v873 = eval.m31_mul(m31_2, cube_252_output_limb_3_col55);
    let wg_v874 = eval.m31_sub(wg_v872, wg_v873);
    let wg_v875 = eval.m31_add(wg_v874, poseidon_round_keys_output_limb_23_col85);
    let wg_v876 = eval.m31_sub(wg_v875, combination_limb_3_col117);
    let carry_3_tmp_1400f_33 = eval.m31_mul(wg_v876, m31_16);
    let wg_v877 = eval.m31_add(carry_3_tmp_1400f_33, cube_252_output_limb_4_col36);
    let wg_v878 = eval.m31_add(wg_v877, cube_252_output_limb_4_col46);
    let wg_v879 = eval.m31_mul(m31_2, cube_252_output_limb_4_col56);
    let wg_v880 = eval.m31_sub(wg_v878, wg_v879);
    let wg_v881 = eval.m31_add(wg_v880, poseidon_round_keys_output_limb_24_col86);
    let wg_v882 = eval.m31_sub(wg_v881, combination_limb_4_col118);
    let carry_4_tmp_1400f_34 = eval.m31_mul(wg_v882, m31_16);
    let wg_v883 = eval.m31_add(carry_4_tmp_1400f_34, cube_252_output_limb_5_col37);
    let wg_v884 = eval.m31_add(wg_v883, cube_252_output_limb_5_col47);
    let wg_v885 = eval.m31_mul(m31_2, cube_252_output_limb_5_col57);
    let wg_v886 = eval.m31_sub(wg_v884, wg_v885);
    let wg_v887 = eval.m31_add(wg_v886, poseidon_round_keys_output_limb_25_col87);
    let wg_v888 = eval.m31_sub(wg_v887, combination_limb_5_col119);
    let carry_5_tmp_1400f_35 = eval.m31_mul(wg_v888, m31_16);
    let wg_v889 = eval.m31_add(carry_5_tmp_1400f_35, cube_252_output_limb_6_col38);
    let wg_v890 = eval.m31_add(wg_v889, cube_252_output_limb_6_col48);
    let wg_v891 = eval.m31_mul(m31_2, cube_252_output_limb_6_col58);
    let wg_v892 = eval.m31_sub(wg_v890, wg_v891);
    let wg_v893 = eval.m31_add(wg_v892, poseidon_round_keys_output_limb_26_col88);
    let wg_v894 = eval.m31_sub(wg_v893, combination_limb_6_col120);
    let carry_6_tmp_1400f_36 = eval.m31_mul(wg_v894, m31_16);
    let wg_v895 = eval.m31_add(carry_6_tmp_1400f_36, cube_252_output_limb_7_col39);
    let wg_v896 = eval.m31_add(wg_v895, cube_252_output_limb_7_col49);
    let wg_v897 = eval.m31_mul(m31_2, cube_252_output_limb_7_col59);
    let wg_v898 = eval.m31_sub(wg_v896, wg_v897);
    let wg_v899 = eval.m31_add(wg_v898, poseidon_round_keys_output_limb_27_col89);
    let wg_v900 = eval.m31_sub(wg_v899, combination_limb_7_col121);
    let wg_v901 = eval.m31_mul(p_coef_col124, m31_136);
    let wg_v902 = eval.m31_sub(wg_v900, wg_v901);
    let carry_7_tmp_1400f_37 = eval.m31_mul(wg_v902, m31_16);
    let wg_v903 = eval.m31_add(carry_7_tmp_1400f_37, cube_252_output_limb_8_col40);
    let wg_v904 = eval.m31_add(wg_v903, cube_252_output_limb_8_col50);
    let wg_v905 = eval.m31_mul(m31_2, cube_252_output_limb_8_col60);
    let wg_v906 = eval.m31_sub(wg_v904, wg_v905);
    let wg_v907 = eval.m31_add(wg_v906, poseidon_round_keys_output_limb_28_col90);
    let wg_v908 = eval.m31_sub(wg_v907, combination_limb_8_col122);
    let carry_8_tmp_1400f_38 = eval.m31_mul(wg_v908, m31_16);
    let wg_v909 = eval.m31_add(p_coef_col124, m31_3);
    let wg_v910 = eval.m31_add(carry_0_tmp_1400f_30, m31_3);
    let wg_v911 = eval.m31_add(carry_1_tmp_1400f_31, m31_3);
    let wg_v912 = eval.m31_add(carry_2_tmp_1400f_32, m31_3);
    let wg_v913 = eval.m31_add(carry_3_tmp_1400f_33, m31_3);
    eval.set_sub_input_word(51, wg_v909);
    eval.set_sub_input_word(52, wg_v910);
    eval.set_sub_input_word(53, wg_v911);
    eval.set_sub_input_word(54, wg_v912);
    eval.set_sub_input_word(55, wg_v913);
    eval.set_lookup_word(119, m31_502259093);
    let wg_v914 = eval.m31_add(p_coef_col124, m31_3);
    eval.set_lookup_word(120, wg_v914);
    let wg_v915 = eval.m31_add(carry_0_tmp_1400f_30, m31_3);
    eval.set_lookup_word(121, wg_v915);
    let wg_v916 = eval.m31_add(carry_1_tmp_1400f_31, m31_3);
    eval.set_lookup_word(122, wg_v916);
    let wg_v917 = eval.m31_add(carry_2_tmp_1400f_32, m31_3);
    eval.set_lookup_word(123, wg_v917);
    let wg_v918 = eval.m31_add(carry_3_tmp_1400f_33, m31_3);
    eval.set_lookup_word(124, wg_v918);
    let wg_v919 = eval.m31_add(carry_4_tmp_1400f_34, m31_3);
    let wg_v920 = eval.m31_add(carry_5_tmp_1400f_35, m31_3);
    let wg_v921 = eval.m31_add(carry_6_tmp_1400f_36, m31_3);
    let wg_v922 = eval.m31_add(carry_7_tmp_1400f_37, m31_3);
    let wg_v923 = eval.m31_add(carry_8_tmp_1400f_38, m31_3);
    eval.set_sub_input_word(56, wg_v919);
    eval.set_sub_input_word(57, wg_v920);
    eval.set_sub_input_word(58, wg_v921);
    eval.set_sub_input_word(59, wg_v922);
    eval.set_sub_input_word(60, wg_v923);
    eval.set_lookup_word(125, m31_502259093);
    let wg_v924 = eval.m31_add(carry_4_tmp_1400f_34, m31_3);
    eval.set_lookup_word(126, wg_v924);
    let wg_v925 = eval.m31_add(carry_5_tmp_1400f_35, m31_3);
    eval.set_lookup_word(127, wg_v925);
    let wg_v926 = eval.m31_add(carry_6_tmp_1400f_36, m31_3);
    eval.set_lookup_word(128, wg_v926);
    let wg_v927 = eval.m31_add(carry_7_tmp_1400f_37, m31_3);
    eval.set_lookup_word(129, wg_v927);
    let wg_v928 = eval.m31_add(carry_8_tmp_1400f_38, m31_3);
    eval.set_lookup_word(130, wg_v928);
    let linear_combination_n_4_coefs_1_1_m2_1_output_tmp_1400f_39 = combination_tmp_1400f_28;
    let enabler_col125 = eval.enabler();
    eval.set_col(125, enabler_col125);
    eval.set_lookup_word(131, m31_1480369132);
    eval.set_lookup_word(132, input_limb_0_col0);
    eval.set_lookup_word(133, input_limb_1_col1);
    eval.set_lookup_word(134, input_limb_2_col2);
    eval.set_lookup_word(135, input_limb_3_col3);
    eval.set_lookup_word(136, input_limb_4_col4);
    eval.set_lookup_word(137, input_limb_5_col5);
    eval.set_lookup_word(138, input_limb_6_col6);
    eval.set_lookup_word(139, input_limb_7_col7);
    eval.set_lookup_word(140, input_limb_8_col8);
    eval.set_lookup_word(141, input_limb_9_col9);
    eval.set_lookup_word(142, input_limb_10_col10);
    eval.set_lookup_word(143, input_limb_11_col11);
    eval.set_lookup_word(144, input_limb_12_col12);
    eval.set_lookup_word(145, input_limb_13_col13);
    eval.set_lookup_word(146, input_limb_14_col14);
    eval.set_lookup_word(147, input_limb_15_col15);
    eval.set_lookup_word(148, input_limb_16_col16);
    eval.set_lookup_word(149, input_limb_17_col17);
    eval.set_lookup_word(150, input_limb_18_col18);
    eval.set_lookup_word(151, input_limb_19_col19);
    eval.set_lookup_word(152, input_limb_20_col20);
    eval.set_lookup_word(153, input_limb_21_col21);
    eval.set_lookup_word(154, input_limb_22_col22);
    eval.set_lookup_word(155, input_limb_23_col23);
    eval.set_lookup_word(156, input_limb_24_col24);
    eval.set_lookup_word(157, input_limb_25_col25);
    eval.set_lookup_word(158, input_limb_26_col26);
    eval.set_lookup_word(159, input_limb_27_col27);
    eval.set_lookup_word(160, input_limb_28_col28);
    eval.set_lookup_word(161, input_limb_29_col29);
    eval.set_lookup_word(162, input_limb_30_col30);
    eval.set_lookup_word(163, input_limb_31_col31);
    eval.set_lookup_word(164, m31_1480369132);
    eval.set_lookup_word(165, input_limb_0_col0);
    let wg_v929 = eval.m31_add(input_limb_1_col1, m31_1);
    eval.set_lookup_word(166, wg_v929);
    eval.set_lookup_word(167, combination_limb_0_col92);
    eval.set_lookup_word(168, combination_limb_1_col93);
    eval.set_lookup_word(169, combination_limb_2_col94);
    eval.set_lookup_word(170, combination_limb_3_col95);
    eval.set_lookup_word(171, combination_limb_4_col96);
    eval.set_lookup_word(172, combination_limb_5_col97);
    eval.set_lookup_word(173, combination_limb_6_col98);
    eval.set_lookup_word(174, combination_limb_7_col99);
    eval.set_lookup_word(175, combination_limb_8_col100);
    eval.set_lookup_word(176, combination_limb_9_col101);
    eval.set_lookup_word(177, combination_limb_0_col103);
    eval.set_lookup_word(178, combination_limb_1_col104);
    eval.set_lookup_word(179, combination_limb_2_col105);
    eval.set_lookup_word(180, combination_limb_3_col106);
    eval.set_lookup_word(181, combination_limb_4_col107);
    eval.set_lookup_word(182, combination_limb_5_col108);
    eval.set_lookup_word(183, combination_limb_6_col109);
    eval.set_lookup_word(184, combination_limb_7_col110);
    eval.set_lookup_word(185, combination_limb_8_col111);
    eval.set_lookup_word(186, combination_limb_9_col112);
    eval.set_lookup_word(187, combination_limb_0_col114);
    eval.set_lookup_word(188, combination_limb_1_col115);
    eval.set_lookup_word(189, combination_limb_2_col116);
    eval.set_lookup_word(190, combination_limb_3_col117);
    eval.set_lookup_word(191, combination_limb_4_col118);
    eval.set_lookup_word(192, combination_limb_5_col119);
    eval.set_lookup_word(193, combination_limb_6_col120);
    eval.set_lookup_word(194, combination_limb_7_col121);
    eval.set_lookup_word(195, combination_limb_8_col122);
    eval.set_lookup_word(196, combination_limb_9_col123);
    eval.set_lookup_word(197, m31_1);
    eval.set_lookup_word(198, enabler_col125);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `poseidon_full_round_chain_row_body` on a per-row `SimdWitnessEval`, then reconstructs the
/// concrete `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    cube_252_state: &cube_252::ClaimGenerator,
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
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
    let Felt252_0_0_0_0 = PackedFelt252::broadcast(Felt252::from([0, 0, 0, 0]));
    let Felt252_1_0_0_0 = PackedFelt252::broadcast(Felt252::from([1, 0, 0, 0]));
    let Felt252_2_0_0_0 = PackedFelt252::broadcast(Felt252::from([2, 0, 0, 0]));
    let Felt252_3_0_0_0 = PackedFelt252::broadcast(Felt252::from([3, 0, 0, 0]));
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
            |(
                row_index,
                (row, lookup_data, sub_component_inputs, poseidon_full_round_chain_input),
            )| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    None,
                    vec![
                        poseidon_full_round_chain_input.0.into_simd(),
                        poseidon_full_round_chain_input.1.into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(0).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(1).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(2).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(3).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(4).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(5).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(6).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(7).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(8).into_simd(),
                        poseidon_full_round_chain_input.2[0].get_m31(9).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(0).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(1).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(2).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(3).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(4).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(5).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(6).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(7).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(8).into_simd(),
                        poseidon_full_round_chain_input.2[1].get_m31(9).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(0).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(1).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(2).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(3).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(4).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(5).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(6).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(7).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(8).into_simd(),
                        poseidon_full_round_chain_input.2[2].get_m31(9).into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                poseidon_full_round_chain_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.cube_252_0 = [
                    lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10],
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                ];
                *lookup_data.cube_252_1 = [
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30],
                    lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40],
                    lw[41],
                ];
                *lookup_data.cube_252_2 = [
                    lw[42], lw[43], lw[44], lw[45], lw[46], lw[47], lw[48], lw[49], lw[50], lw[51],
                    lw[52], lw[53], lw[54], lw[55], lw[56], lw[57], lw[58], lw[59], lw[60], lw[61],
                    lw[62],
                ];
                *lookup_data.poseidon_round_keys_3 = [
                    lw[63], lw[64], lw[65], lw[66], lw[67], lw[68], lw[69], lw[70], lw[71], lw[72],
                    lw[73], lw[74], lw[75], lw[76], lw[77], lw[78], lw[79], lw[80], lw[81], lw[82],
                    lw[83], lw[84], lw[85], lw[86], lw[87], lw[88], lw[89], lw[90], lw[91], lw[92],
                    lw[93], lw[94],
                ];
                *lookup_data.range_check_3_3_3_3_3_4 =
                    [lw[95], lw[96], lw[97], lw[98], lw[99], lw[100]];
                *lookup_data.range_check_3_3_3_3_3_5 =
                    [lw[101], lw[102], lw[103], lw[104], lw[105], lw[106]];
                *lookup_data.range_check_3_3_3_3_3_6 =
                    [lw[107], lw[108], lw[109], lw[110], lw[111], lw[112]];
                *lookup_data.range_check_3_3_3_3_3_7 =
                    [lw[113], lw[114], lw[115], lw[116], lw[117], lw[118]];
                *lookup_data.range_check_3_3_3_3_3_8 =
                    [lw[119], lw[120], lw[121], lw[122], lw[123], lw[124]];
                *lookup_data.range_check_3_3_3_3_3_9 =
                    [lw[125], lw[126], lw[127], lw[128], lw[129], lw[130]];
                *lookup_data.poseidon_full_round_chain_10 = [
                    lw[131], lw[132], lw[133], lw[134], lw[135], lw[136], lw[137], lw[138],
                    lw[139], lw[140], lw[141], lw[142], lw[143], lw[144], lw[145], lw[146],
                    lw[147], lw[148], lw[149], lw[150], lw[151], lw[152], lw[153], lw[154],
                    lw[155], lw[156], lw[157], lw[158], lw[159], lw[160], lw[161], lw[162],
                    lw[163],
                ];
                *lookup_data.poseidon_full_round_chain_11 = [
                    lw[164], lw[165], lw[166], lw[167], lw[168], lw[169], lw[170], lw[171],
                    lw[172], lw[173], lw[174], lw[175], lw[176], lw[177], lw[178], lw[179],
                    lw[180], lw[181], lw[182], lw[183], lw[184], lw[185], lw[186], lw[187],
                    lw[188], lw[189], lw[190], lw[191], lw[192], lw[193], lw[194], lw[195],
                    lw[196],
                ];
                *lookup_data.mults_0 = lw[197];
                *lookup_data.mults_1 = lw[198];
                let sw = eval.sub_scratch();
                *sub_component_inputs.cube_252[0] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[0]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[3]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[4]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                ]);
                *sub_component_inputs.cube_252[1] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[15]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[18]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                ]);
                *sub_component_inputs.cube_252[2] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[21]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[23]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[24]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[25]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[26]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[27]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[28]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[29]) },
                ]);
                *sub_component_inputs.poseidon_round_keys[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[30]) }];
                *sub_component_inputs.range_check_3_3_3_3_3[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[31]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[32]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[33]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[34]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[35]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[36]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[37]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[38]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[39]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[40]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[41]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[42]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[43]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[44]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[45]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[46]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[48]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[49]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[50]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[4] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[51]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[52]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[53]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[54]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[55]) },
                ];
                *sub_component_inputs.range_check_3_3_3_3_3[5] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[56]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[57]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[58]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[59]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[60]) },
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
        self,
        cube_252_state: &cube_252::ClaimGenerator,
        poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
        range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut packed_inputs = self.packed_inputs.into_inner().unwrap();
        assert!(!packed_inputs.is_empty());
        assert!(self.remainder_inputs.lock().unwrap().is_empty());
        let n_vec_rows = packed_inputs.len();
        let n_rows = n_vec_rows * N_LANES;
        let packed_size = n_vec_rows.next_power_of_two();
        let log_size = packed_size.ilog2() + LOG_N_LANES;
        packed_inputs.resize(packed_size, *packed_inputs.first().unwrap());
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            packed_inputs,
            n_rows,
            cube_252_state,
            poseidon_round_keys_state,
            range_check_3_3_3_3_3_state,
        );
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.poseidon_round_keys {
            add_inputs(
                poseidon_round_keys_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_3_3_3_3_3 {
            add_inputs(
                range_check_3_3_3_3_3_state,
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

/// Record the `poseidon_full_round_chain` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_poseidon_full_round_chain() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("poseidon_full_round_chain", 32, Some(33));
    poseidon_full_round_chain_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    199;
    cube_252_0: 21,
    cube_252_1: 21,
    cube_252_2: 21,
    poseidon_round_keys_3: 32,
    range_check_3_3_3_3_3_4: 6,
    range_check_3_3_3_3_3_5: 6,
    range_check_3_3_3_3_3_6: 6,
    range_check_3_3_3_3_3_7: 6,
    range_check_3_3_3_3_3_8: 6,
    range_check_3_3_3_3_3_9: 6,
    poseidon_full_round_chain_10: 33,
    poseidon_full_round_chain_11: 33,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("cube_252", 0, "cube_252_state", 0, 0, 10),
    ("cube_252", 1, "cube_252_state", 0, 10, 10),
    ("cube_252", 2, "cube_252_state", 0, 20, 10),
    (
        "poseidon_round_keys",
        0,
        "poseidon_round_keys_state",
        0,
        30,
        1,
    ),
    (
        "range_check_3_3_3_3_3",
        0,
        "range_check_3_3_3_3_3_state",
        0,
        31,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        1,
        "range_check_3_3_3_3_3_state",
        0,
        36,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        2,
        "range_check_3_3_3_3_3_state",
        0,
        41,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        3,
        "range_check_3_3_3_3_3_state",
        0,
        46,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        4,
        "range_check_3_3_3_3_3_state",
        0,
        51,
        5,
    ),
    (
        "range_check_3_3_3_3_3",
        5,
        "range_check_3_3_3_3_3_state",
        0,
        56,
        5,
    ),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "cube_252_0",
        "mults_0",
        false,
        "cube_252_1",
        "mults_0",
        false,
    ),
    (
        "cube_252_2",
        "mults_0",
        false,
        "poseidon_round_keys_3",
        "mults_0",
        false,
    ),
    (
        "range_check_3_3_3_3_3_4",
        "mults_0",
        false,
        "range_check_3_3_3_3_3_5",
        "mults_0",
        false,
    ),
    (
        "range_check_3_3_3_3_3_6",
        "mults_0",
        false,
        "range_check_3_3_3_3_3_7",
        "mults_0",
        false,
    ),
    (
        "range_check_3_3_3_3_3_8",
        "mults_0",
        false,
        "range_check_3_3_3_3_3_9",
        "mults_0",
        false,
    ),
    (
        "poseidon_full_round_chain_10",
        "mults_1",
        false,
        "poseidon_full_round_chain_11",
        "mults_1",
        true,
    ),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.cube_252_0.iter().flatten().copied().collect(),
        ld.cube_252_1.iter().flatten().copied().collect(),
        ld.cube_252_2.iter().flatten().copied().collect(),
        ld.poseidon_round_keys_3.iter().flatten().copied().collect(),
        ld.range_check_3_3_3_3_3_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_6
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_7
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_8
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_3_3_3_3_3_9
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_full_round_chain_10
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_full_round_chain_11
            .iter()
            .flatten()
            .copied()
            .collect(),
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
        sci.cube_252[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.cube_252[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.cube_252[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t.get_m31(0).into_simd(),
                    t.get_m31(1).into_simd(),
                    t.get_m31(2).into_simd(),
                    t.get_m31(3).into_simd(),
                    t.get_m31(4).into_simd(),
                    t.get_m31(5).into_simd(),
                    t.get_m31(6).into_simd(),
                    t.get_m31(7).into_simd(),
                    t.get_m31(8).into_simd(),
                    t.get_m31(9).into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.poseidon_round_keys[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_3_3_3_3_3[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                    t[4].into_simd(),
                ]
            })
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
    cube_252_state: &cube_252::ClaimGenerator,
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    range_check_3_3_3_3_3_state: &range_check_3_3_3_3_3::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        cube_252_state,
        poseidon_round_keys_state,
        range_check_3_3_3_3_3_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        cube_252_state,
        poseidon_round_keys_state,
        range_check_3_3_3_3_3_state,
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
    cube_252_0: Vec<[PackedM31; 21]>,
    cube_252_1: Vec<[PackedM31; 21]>,
    cube_252_2: Vec<[PackedM31; 21]>,
    poseidon_round_keys_3: Vec<[PackedM31; 32]>,
    range_check_3_3_3_3_3_4: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_5: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_6: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_7: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_8: Vec<[PackedM31; 6]>,
    range_check_3_3_3_3_3_9: Vec<[PackedM31; 6]>,
    poseidon_full_round_chain_10: Vec<[PackedM31; 33]>,
    poseidon_full_round_chain_11: Vec<[PackedM31; 33]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    cube_252_0: 21,
    cube_252_1: 21,
    cube_252_2: 21,
    poseidon_round_keys_3: 32,
    range_check_3_3_3_3_3_4: 6,
    range_check_3_3_3_3_3_5: 6,
    range_check_3_3_3_3_3_6: 6,
    range_check_3_3_3_3_3_7: 6,
    range_check_3_3_3_3_3_8: 6,
    range_check_3_3_3_3_3_9: 6,
    poseidon_full_round_chain_10: 33,
    poseidon_full_round_chain_11: 33,
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
            &self.lookup_data.cube_252_0,
            &self.lookup_data.cube_252_1,
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
            &self.lookup_data.cube_252_2,
            &self.lookup_data.poseidon_round_keys_3,
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
            &self.lookup_data.range_check_3_3_3_3_3_4,
            &self.lookup_data.range_check_3_3_3_3_3_5,
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
            &self.lookup_data.range_check_3_3_3_3_3_6,
            &self.lookup_data.range_check_3_3_3_3_3_7,
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
            &self.lookup_data.range_check_3_3_3_3_3_8,
            &self.lookup_data.range_check_3_3_3_3_3_9,
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
            &self.lookup_data.poseidon_full_round_chain_10,
            &self.lookup_data.poseidon_full_round_chain_11,
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
