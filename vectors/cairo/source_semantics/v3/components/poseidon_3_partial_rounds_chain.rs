// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::poseidon_3_partial_rounds_chain::{
    Claim, InteractionClaim, N_TRACE_COLUMNS,
};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    cube_252, poseidon_round_keys, range_check_252_width_27, range_check_4_4, range_check_4_4_4_4,
};
use crate::witness::prelude::*;

pub type InputType = (M31, M31, [Felt252Width27; 4]);
pub type PackedInputType = (PackedM31, PackedM31, [PackedFelt252Width27; 4]);

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
        poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
        cube_252_state: &cube_252::ClaimGenerator,
        range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
        range_check_4_4_state: &range_check_4_4::ClaimGenerator,
        range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
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
            poseidon_round_keys_state,
            cube_252_state,
            range_check_4_4_4_4_state,
            range_check_4_4_state,
            range_check_252_width_27_state,
        );
        for inputs in sub_component_inputs.poseidon_round_keys {
            add_inputs(
                poseidon_round_keys_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_4_4_4_4 {
            add_inputs(
                range_check_4_4_4_4_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4 {
            add_inputs(range_check_4_4_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_252_width_27 {
            add_inputs(
                range_check_252_width_27_state,
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
    poseidon_round_keys: [Vec<poseidon_round_keys::PackedInputType>; 1],
    cube_252: [Vec<cube_252::PackedInputType>; 3],
    range_check_4_4_4_4: [Vec<range_check_4_4_4_4::PackedInputType>; 6],
    range_check_4_4: [Vec<range_check_4_4::PackedInputType>; 3],
    range_check_252_width_27: [Vec<range_check_252_width_27::PackedInputType>; 3],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
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
    let Felt252_4_0_0_0 = PackedFelt252::broadcast(Felt252::from([4, 0, 0, 0]));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1024310512 = PackedM31::broadcast(M31::from(1024310512));
    let M31_1027333874 = PackedM31::broadcast(M31::from(1027333874));
    let M31_1090315331 = PackedM31::broadcast(M31::from(1090315331));
    let M31_134217729 = PackedM31::broadcast(M31::from(134217729));
    let M31_1343313504 = PackedM31::broadcast(M31::from(1343313504));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1651211826 = PackedM31::broadcast(M31::from(1651211826));
    let M31_1987997202 = PackedM31::broadcast(M31::from(1987997202));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_268435458 = PackedM31::broadcast(M31::from(268435458));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_4 = PackedM31::broadcast(M31::from(4));
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
                (row, lookup_data, sub_component_inputs, poseidon_3_partial_rounds_chain_input),
            )| {
                let input_limb_0_col0 = poseidon_3_partial_rounds_chain_input.0;
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = poseidon_3_partial_rounds_chain_input.1;
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(0);
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(1);
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(2);
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(3);
                *row[5] = input_limb_5_col5;
                let input_limb_6_col6 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(4);
                *row[6] = input_limb_6_col6;
                let input_limb_7_col7 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(5);
                *row[7] = input_limb_7_col7;
                let input_limb_8_col8 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(6);
                *row[8] = input_limb_8_col8;
                let input_limb_9_col9 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(7);
                *row[9] = input_limb_9_col9;
                let input_limb_10_col10 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(8);
                *row[10] = input_limb_10_col10;
                let input_limb_11_col11 = poseidon_3_partial_rounds_chain_input.2[0].get_m31(9);
                *row[11] = input_limb_11_col11;
                let input_limb_12_col12 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(0);
                *row[12] = input_limb_12_col12;
                let input_limb_13_col13 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(1);
                *row[13] = input_limb_13_col13;
                let input_limb_14_col14 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(2);
                *row[14] = input_limb_14_col14;
                let input_limb_15_col15 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(3);
                *row[15] = input_limb_15_col15;
                let input_limb_16_col16 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(4);
                *row[16] = input_limb_16_col16;
                let input_limb_17_col17 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(5);
                *row[17] = input_limb_17_col17;
                let input_limb_18_col18 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(6);
                *row[18] = input_limb_18_col18;
                let input_limb_19_col19 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(7);
                *row[19] = input_limb_19_col19;
                let input_limb_20_col20 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(8);
                *row[20] = input_limb_20_col20;
                let input_limb_21_col21 = poseidon_3_partial_rounds_chain_input.2[1].get_m31(9);
                *row[21] = input_limb_21_col21;
                let input_limb_22_col22 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(0);
                *row[22] = input_limb_22_col22;
                let input_limb_23_col23 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(1);
                *row[23] = input_limb_23_col23;
                let input_limb_24_col24 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(2);
                *row[24] = input_limb_24_col24;
                let input_limb_25_col25 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(3);
                *row[25] = input_limb_25_col25;
                let input_limb_26_col26 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(4);
                *row[26] = input_limb_26_col26;
                let input_limb_27_col27 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(5);
                *row[27] = input_limb_27_col27;
                let input_limb_28_col28 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(6);
                *row[28] = input_limb_28_col28;
                let input_limb_29_col29 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(7);
                *row[29] = input_limb_29_col29;
                let input_limb_30_col30 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(8);
                *row[30] = input_limb_30_col30;
                let input_limb_31_col31 = poseidon_3_partial_rounds_chain_input.2[2].get_m31(9);
                *row[31] = input_limb_31_col31;
                let input_limb_32_col32 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(0);
                *row[32] = input_limb_32_col32;
                let input_limb_33_col33 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(1);
                *row[33] = input_limb_33_col33;
                let input_limb_34_col34 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(2);
                *row[34] = input_limb_34_col34;
                let input_limb_35_col35 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(3);
                *row[35] = input_limb_35_col35;
                let input_limb_36_col36 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(4);
                *row[36] = input_limb_36_col36;
                let input_limb_37_col37 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(5);
                *row[37] = input_limb_37_col37;
                let input_limb_38_col38 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(6);
                *row[38] = input_limb_38_col38;
                let input_limb_39_col39 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(7);
                *row[39] = input_limb_39_col39;
                let input_limb_40_col40 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(8);
                *row[40] = input_limb_40_col40;
                let input_limb_41_col41 = poseidon_3_partial_rounds_chain_input.2[3].get_m31(9);
                *row[41] = input_limb_41_col41;
                *sub_component_inputs.poseidon_round_keys[0] = [input_limb_1_col1];
                let poseidon_round_keys_output_tmp_8c14f_0 =
                    PackedPoseidonRoundKeys::deduce_output([input_limb_1_col1]);
                let poseidon_round_keys_output_limb_0_col42 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(0);
                *row[42] = poseidon_round_keys_output_limb_0_col42;
                let poseidon_round_keys_output_limb_1_col43 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(1);
                *row[43] = poseidon_round_keys_output_limb_1_col43;
                let poseidon_round_keys_output_limb_2_col44 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(2);
                *row[44] = poseidon_round_keys_output_limb_2_col44;
                let poseidon_round_keys_output_limb_3_col45 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(3);
                *row[45] = poseidon_round_keys_output_limb_3_col45;
                let poseidon_round_keys_output_limb_4_col46 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(4);
                *row[46] = poseidon_round_keys_output_limb_4_col46;
                let poseidon_round_keys_output_limb_5_col47 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(5);
                *row[47] = poseidon_round_keys_output_limb_5_col47;
                let poseidon_round_keys_output_limb_6_col48 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(6);
                *row[48] = poseidon_round_keys_output_limb_6_col48;
                let poseidon_round_keys_output_limb_7_col49 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(7);
                *row[49] = poseidon_round_keys_output_limb_7_col49;
                let poseidon_round_keys_output_limb_8_col50 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(8);
                *row[50] = poseidon_round_keys_output_limb_8_col50;
                let poseidon_round_keys_output_limb_9_col51 =
                    poseidon_round_keys_output_tmp_8c14f_0[0].get_m31(9);
                *row[51] = poseidon_round_keys_output_limb_9_col51;
                let poseidon_round_keys_output_limb_10_col52 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(0);
                *row[52] = poseidon_round_keys_output_limb_10_col52;
                let poseidon_round_keys_output_limb_11_col53 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(1);
                *row[53] = poseidon_round_keys_output_limb_11_col53;
                let poseidon_round_keys_output_limb_12_col54 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(2);
                *row[54] = poseidon_round_keys_output_limb_12_col54;
                let poseidon_round_keys_output_limb_13_col55 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(3);
                *row[55] = poseidon_round_keys_output_limb_13_col55;
                let poseidon_round_keys_output_limb_14_col56 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(4);
                *row[56] = poseidon_round_keys_output_limb_14_col56;
                let poseidon_round_keys_output_limb_15_col57 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(5);
                *row[57] = poseidon_round_keys_output_limb_15_col57;
                let poseidon_round_keys_output_limb_16_col58 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(6);
                *row[58] = poseidon_round_keys_output_limb_16_col58;
                let poseidon_round_keys_output_limb_17_col59 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(7);
                *row[59] = poseidon_round_keys_output_limb_17_col59;
                let poseidon_round_keys_output_limb_18_col60 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(8);
                *row[60] = poseidon_round_keys_output_limb_18_col60;
                let poseidon_round_keys_output_limb_19_col61 =
                    poseidon_round_keys_output_tmp_8c14f_0[1].get_m31(9);
                *row[61] = poseidon_round_keys_output_limb_19_col61;
                let poseidon_round_keys_output_limb_20_col62 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(0);
                *row[62] = poseidon_round_keys_output_limb_20_col62;
                let poseidon_round_keys_output_limb_21_col63 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(1);
                *row[63] = poseidon_round_keys_output_limb_21_col63;
                let poseidon_round_keys_output_limb_22_col64 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(2);
                *row[64] = poseidon_round_keys_output_limb_22_col64;
                let poseidon_round_keys_output_limb_23_col65 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(3);
                *row[65] = poseidon_round_keys_output_limb_23_col65;
                let poseidon_round_keys_output_limb_24_col66 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(4);
                *row[66] = poseidon_round_keys_output_limb_24_col66;
                let poseidon_round_keys_output_limb_25_col67 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(5);
                *row[67] = poseidon_round_keys_output_limb_25_col67;
                let poseidon_round_keys_output_limb_26_col68 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(6);
                *row[68] = poseidon_round_keys_output_limb_26_col68;
                let poseidon_round_keys_output_limb_27_col69 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(7);
                *row[69] = poseidon_round_keys_output_limb_27_col69;
                let poseidon_round_keys_output_limb_28_col70 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(8);
                *row[70] = poseidon_round_keys_output_limb_28_col70;
                let poseidon_round_keys_output_limb_29_col71 =
                    poseidon_round_keys_output_tmp_8c14f_0[2].get_m31(9);
                *row[71] = poseidon_round_keys_output_limb_29_col71;
                *lookup_data.poseidon_round_keys_0 = [
                    M31_1024310512,
                    input_limb_1_col1,
                    poseidon_round_keys_output_limb_0_col42,
                    poseidon_round_keys_output_limb_1_col43,
                    poseidon_round_keys_output_limb_2_col44,
                    poseidon_round_keys_output_limb_3_col45,
                    poseidon_round_keys_output_limb_4_col46,
                    poseidon_round_keys_output_limb_5_col47,
                    poseidon_round_keys_output_limb_6_col48,
                    poseidon_round_keys_output_limb_7_col49,
                    poseidon_round_keys_output_limb_8_col50,
                    poseidon_round_keys_output_limb_9_col51,
                    poseidon_round_keys_output_limb_10_col52,
                    poseidon_round_keys_output_limb_11_col53,
                    poseidon_round_keys_output_limb_12_col54,
                    poseidon_round_keys_output_limb_13_col55,
                    poseidon_round_keys_output_limb_14_col56,
                    poseidon_round_keys_output_limb_15_col57,
                    poseidon_round_keys_output_limb_16_col58,
                    poseidon_round_keys_output_limb_17_col59,
                    poseidon_round_keys_output_limb_18_col60,
                    poseidon_round_keys_output_limb_19_col61,
                    poseidon_round_keys_output_limb_20_col62,
                    poseidon_round_keys_output_limb_21_col63,
                    poseidon_round_keys_output_limb_22_col64,
                    poseidon_round_keys_output_limb_23_col65,
                    poseidon_round_keys_output_limb_24_col66,
                    poseidon_round_keys_output_limb_25_col67,
                    poseidon_round_keys_output_limb_26_col68,
                    poseidon_round_keys_output_limb_27_col69,
                    poseidon_round_keys_output_limb_28_col70,
                    poseidon_round_keys_output_limb_29_col71,
                ];

                // Poseidon Partial Round.

                *sub_component_inputs.cube_252[0] = poseidon_3_partial_rounds_chain_input.2[3];
                let cube_252_output_tmp_8c14f_1 =
                    PackedCube252::deduce_output(poseidon_3_partial_rounds_chain_input.2[3]);
                let cube_252_output_limb_0_col72 = cube_252_output_tmp_8c14f_1.get_m31(0);
                *row[72] = cube_252_output_limb_0_col72;
                let cube_252_output_limb_1_col73 = cube_252_output_tmp_8c14f_1.get_m31(1);
                *row[73] = cube_252_output_limb_1_col73;
                let cube_252_output_limb_2_col74 = cube_252_output_tmp_8c14f_1.get_m31(2);
                *row[74] = cube_252_output_limb_2_col74;
                let cube_252_output_limb_3_col75 = cube_252_output_tmp_8c14f_1.get_m31(3);
                *row[75] = cube_252_output_limb_3_col75;
                let cube_252_output_limb_4_col76 = cube_252_output_tmp_8c14f_1.get_m31(4);
                *row[76] = cube_252_output_limb_4_col76;
                let cube_252_output_limb_5_col77 = cube_252_output_tmp_8c14f_1.get_m31(5);
                *row[77] = cube_252_output_limb_5_col77;
                let cube_252_output_limb_6_col78 = cube_252_output_tmp_8c14f_1.get_m31(6);
                *row[78] = cube_252_output_limb_6_col78;
                let cube_252_output_limb_7_col79 = cube_252_output_tmp_8c14f_1.get_m31(7);
                *row[79] = cube_252_output_limb_7_col79;
                let cube_252_output_limb_8_col80 = cube_252_output_tmp_8c14f_1.get_m31(8);
                *row[80] = cube_252_output_limb_8_col80;
                let cube_252_output_limb_9_col81 = cube_252_output_tmp_8c14f_1.get_m31(9);
                *row[81] = cube_252_output_limb_9_col81;
                *lookup_data.cube_252_1 = [
                    M31_1987997202,
                    input_limb_32_col32,
                    input_limb_33_col33,
                    input_limb_34_col34,
                    input_limb_35_col35,
                    input_limb_36_col36,
                    input_limb_37_col37,
                    input_limb_38_col38,
                    input_limb_39_col39,
                    input_limb_40_col40,
                    input_limb_41_col41,
                    cube_252_output_limb_0_col72,
                    cube_252_output_limb_1_col73,
                    cube_252_output_limb_2_col74,
                    cube_252_output_limb_3_col75,
                    cube_252_output_limb_4_col76,
                    cube_252_output_limb_5_col77,
                    cube_252_output_limb_6_col78,
                    cube_252_output_limb_7_col79,
                    cube_252_output_limb_8_col80,
                    cube_252_output_limb_9_col81,
                ];

                // Linear Combination N 6 Coefs 4 2 3 1 M 1 1.

                let combination_tmp_8c14f_2 = PackedFelt252Width27::from_packed_felt252(
                    (((((((Felt252_0_0_0_0)
                        + ((Felt252_4_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[0],
                            ))))
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[1],
                            ))))
                        + ((Felt252_3_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[2],
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[3],
                            ))))
                        - ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_8c14f_1,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_8c14f_0[0],
                            )))),
                );
                let combination_limb_0_col82 = combination_tmp_8c14f_2.get_m31(0);
                *row[82] = combination_limb_0_col82;
                let combination_limb_1_col83 = combination_tmp_8c14f_2.get_m31(1);
                *row[83] = combination_limb_1_col83;
                let combination_limb_2_col84 = combination_tmp_8c14f_2.get_m31(2);
                *row[84] = combination_limb_2_col84;
                let combination_limb_3_col85 = combination_tmp_8c14f_2.get_m31(3);
                *row[85] = combination_limb_3_col85;
                let combination_limb_4_col86 = combination_tmp_8c14f_2.get_m31(4);
                *row[86] = combination_limb_4_col86;
                let combination_limb_5_col87 = combination_tmp_8c14f_2.get_m31(5);
                *row[87] = combination_limb_5_col87;
                let combination_limb_6_col88 = combination_tmp_8c14f_2.get_m31(6);
                *row[88] = combination_limb_6_col88;
                let combination_limb_7_col89 = combination_tmp_8c14f_2.get_m31(7);
                *row[89] = combination_limb_7_col89;
                let combination_limb_8_col90 = combination_tmp_8c14f_2.get_m31(8);
                *row[90] = combination_limb_8_col90;
                let combination_limb_9_col91 = combination_tmp_8c14f_2.get_m31(9);
                *row[91] = combination_limb_9_col91;
                let biased_limb_accumulator_u32_tmp_8c14f_3 = PackedUInt32::from_m31(
                    (((((((((M31_4) * (input_limb_2_col2))
                        + ((M31_2) * (input_limb_12_col12)))
                        + ((M31_3) * (input_limb_22_col22)))
                        + (input_limb_32_col32))
                        - (cube_252_output_limb_0_col72))
                        + (poseidon_round_keys_output_limb_0_col42))
                        - (combination_limb_0_col82))
                        + (M31_268435458)),
                );
                let p_coef_col92 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_3.low().as_m31()) - (M31_2));
                *row[92] = p_coef_col92;
                let carry_0_tmp_8c14f_4 = ((((((((((M31_4) * (input_limb_2_col2))
                    + ((M31_2) * (input_limb_12_col12)))
                    + ((M31_3) * (input_limb_22_col22)))
                    + (input_limb_32_col32))
                    - (cube_252_output_limb_0_col72))
                    + (poseidon_round_keys_output_limb_0_col42))
                    - (combination_limb_0_col82))
                    - (p_coef_col92))
                    * (M31_16));
                let carry_1_tmp_8c14f_5 = (((((((((carry_0_tmp_8c14f_4)
                    + ((M31_4) * (input_limb_3_col3)))
                    + ((M31_2) * (input_limb_13_col13)))
                    + ((M31_3) * (input_limb_23_col23)))
                    + (input_limb_33_col33))
                    - (cube_252_output_limb_1_col73))
                    + (poseidon_round_keys_output_limb_1_col43))
                    - (combination_limb_1_col83))
                    * (M31_16));
                let carry_2_tmp_8c14f_6 = (((((((((carry_1_tmp_8c14f_5)
                    + ((M31_4) * (input_limb_4_col4)))
                    + ((M31_2) * (input_limb_14_col14)))
                    + ((M31_3) * (input_limb_24_col24)))
                    + (input_limb_34_col34))
                    - (cube_252_output_limb_2_col74))
                    + (poseidon_round_keys_output_limb_2_col44))
                    - (combination_limb_2_col84))
                    * (M31_16));
                let carry_3_tmp_8c14f_7 = (((((((((carry_2_tmp_8c14f_6)
                    + ((M31_4) * (input_limb_5_col5)))
                    + ((M31_2) * (input_limb_15_col15)))
                    + ((M31_3) * (input_limb_25_col25)))
                    + (input_limb_35_col35))
                    - (cube_252_output_limb_3_col75))
                    + (poseidon_round_keys_output_limb_3_col45))
                    - (combination_limb_3_col85))
                    * (M31_16));
                let carry_4_tmp_8c14f_8 = (((((((((carry_3_tmp_8c14f_7)
                    + ((M31_4) * (input_limb_6_col6)))
                    + ((M31_2) * (input_limb_16_col16)))
                    + ((M31_3) * (input_limb_26_col26)))
                    + (input_limb_36_col36))
                    - (cube_252_output_limb_4_col76))
                    + (poseidon_round_keys_output_limb_4_col46))
                    - (combination_limb_4_col86))
                    * (M31_16));
                let carry_5_tmp_8c14f_9 = (((((((((carry_4_tmp_8c14f_8)
                    + ((M31_4) * (input_limb_7_col7)))
                    + ((M31_2) * (input_limb_17_col17)))
                    + ((M31_3) * (input_limb_27_col27)))
                    + (input_limb_37_col37))
                    - (cube_252_output_limb_5_col77))
                    + (poseidon_round_keys_output_limb_5_col47))
                    - (combination_limb_5_col87))
                    * (M31_16));
                let carry_6_tmp_8c14f_10 = (((((((((carry_5_tmp_8c14f_9)
                    + ((M31_4) * (input_limb_8_col8)))
                    + ((M31_2) * (input_limb_18_col18)))
                    + ((M31_3) * (input_limb_28_col28)))
                    + (input_limb_38_col38))
                    - (cube_252_output_limb_6_col78))
                    + (poseidon_round_keys_output_limb_6_col48))
                    - (combination_limb_6_col88))
                    * (M31_16));
                let carry_7_tmp_8c14f_11 = ((((((((((carry_6_tmp_8c14f_10)
                    + ((M31_4) * (input_limb_9_col9)))
                    + ((M31_2) * (input_limb_19_col19)))
                    + ((M31_3) * (input_limb_29_col29)))
                    + (input_limb_39_col39))
                    - (cube_252_output_limb_7_col79))
                    + (poseidon_round_keys_output_limb_7_col49))
                    - (combination_limb_7_col89))
                    - ((p_coef_col92) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_12 = (((((((((carry_7_tmp_8c14f_11)
                    + ((M31_4) * (input_limb_10_col10)))
                    + ((M31_2) * (input_limb_20_col20)))
                    + ((M31_3) * (input_limb_30_col30)))
                    + (input_limb_40_col40))
                    - (cube_252_output_limb_8_col80))
                    + (poseidon_round_keys_output_limb_8_col50))
                    - (combination_limb_8_col90))
                    * (M31_16));
                *sub_component_inputs.range_check_4_4_4_4[0] = [
                    ((p_coef_col92) + (M31_2)),
                    ((carry_0_tmp_8c14f_4) + (M31_2)),
                    ((carry_1_tmp_8c14f_5) + (M31_2)),
                    ((carry_2_tmp_8c14f_6) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_2 = [
                    M31_1027333874,
                    ((p_coef_col92) + (M31_2)),
                    ((carry_0_tmp_8c14f_4) + (M31_2)),
                    ((carry_1_tmp_8c14f_5) + (M31_2)),
                    ((carry_2_tmp_8c14f_6) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4_4_4[1] = [
                    ((carry_3_tmp_8c14f_7) + (M31_2)),
                    ((carry_4_tmp_8c14f_8) + (M31_2)),
                    ((carry_5_tmp_8c14f_9) + (M31_2)),
                    ((carry_6_tmp_8c14f_10) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_3 = [
                    M31_1027333874,
                    ((carry_3_tmp_8c14f_7) + (M31_2)),
                    ((carry_4_tmp_8c14f_8) + (M31_2)),
                    ((carry_5_tmp_8c14f_9) + (M31_2)),
                    ((carry_6_tmp_8c14f_10) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4[0] = [
                    ((carry_7_tmp_8c14f_11) + (M31_2)),
                    ((carry_8_tmp_8c14f_12) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4 = [
                    M31_1651211826,
                    ((carry_7_tmp_8c14f_11) + (M31_2)),
                    ((carry_8_tmp_8c14f_12) + (M31_2)),
                ];
                let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13 =
                    combination_tmp_8c14f_2;

                *sub_component_inputs.range_check_252_width_27[0] =
                    linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13;
                *lookup_data.range_check_252_width_27_5 = [
                    M31_1090315331,
                    combination_limb_0_col82,
                    combination_limb_1_col83,
                    combination_limb_2_col84,
                    combination_limb_3_col85,
                    combination_limb_4_col86,
                    combination_limb_5_col87,
                    combination_limb_6_col88,
                    combination_limb_7_col89,
                    combination_limb_8_col90,
                    combination_limb_9_col91,
                ];

                // Linear Combination N 1 Coefs 2.

                let combination_tmp_8c14f_14 = PackedFelt252Width27::from_packed_felt252(
                    ((Felt252_0_0_0_0)
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13,
                            )))),
                );
                let combination_limb_0_col93 = combination_tmp_8c14f_14.get_m31(0);
                *row[93] = combination_limb_0_col93;
                let combination_limb_1_col94 = combination_tmp_8c14f_14.get_m31(1);
                *row[94] = combination_limb_1_col94;
                let combination_limb_2_col95 = combination_tmp_8c14f_14.get_m31(2);
                *row[95] = combination_limb_2_col95;
                let combination_limb_3_col96 = combination_tmp_8c14f_14.get_m31(3);
                *row[96] = combination_limb_3_col96;
                let combination_limb_4_col97 = combination_tmp_8c14f_14.get_m31(4);
                *row[97] = combination_limb_4_col97;
                let combination_limb_5_col98 = combination_tmp_8c14f_14.get_m31(5);
                *row[98] = combination_limb_5_col98;
                let combination_limb_6_col99 = combination_tmp_8c14f_14.get_m31(6);
                *row[99] = combination_limb_6_col99;
                let combination_limb_7_col100 = combination_tmp_8c14f_14.get_m31(7);
                *row[100] = combination_limb_7_col100;
                let combination_limb_8_col101 = combination_tmp_8c14f_14.get_m31(8);
                *row[101] = combination_limb_8_col101;
                let combination_limb_9_col102 = combination_tmp_8c14f_14.get_m31(9);
                *row[102] = combination_limb_9_col102;
                let biased_limb_accumulator_u32_tmp_8c14f_15 = PackedUInt32::from_m31(
                    ((((M31_2) * (combination_limb_0_col82)) - (combination_limb_0_col93))
                        + (M31_134217729)),
                );
                let p_coef_col103 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_15.low().as_m31()) - (M31_1));
                *row[103] = p_coef_col103;
                let carry_0_tmp_8c14f_16 = (((((M31_2) * (combination_limb_0_col82))
                    - (combination_limb_0_col93))
                    - (p_coef_col103))
                    * (M31_16));
                let carry_1_tmp_8c14f_17 = ((((carry_0_tmp_8c14f_16)
                    + ((M31_2) * (combination_limb_1_col83)))
                    - (combination_limb_1_col94))
                    * (M31_16));
                let carry_2_tmp_8c14f_18 = ((((carry_1_tmp_8c14f_17)
                    + ((M31_2) * (combination_limb_2_col84)))
                    - (combination_limb_2_col95))
                    * (M31_16));
                let carry_3_tmp_8c14f_19 = ((((carry_2_tmp_8c14f_18)
                    + ((M31_2) * (combination_limb_3_col85)))
                    - (combination_limb_3_col96))
                    * (M31_16));
                let carry_4_tmp_8c14f_20 = ((((carry_3_tmp_8c14f_19)
                    + ((M31_2) * (combination_limb_4_col86)))
                    - (combination_limb_4_col97))
                    * (M31_16));
                let carry_5_tmp_8c14f_21 = ((((carry_4_tmp_8c14f_20)
                    + ((M31_2) * (combination_limb_5_col87)))
                    - (combination_limb_5_col98))
                    * (M31_16));
                let carry_6_tmp_8c14f_22 = ((((carry_5_tmp_8c14f_21)
                    + ((M31_2) * (combination_limb_6_col88)))
                    - (combination_limb_6_col99))
                    * (M31_16));
                let carry_7_tmp_8c14f_23 = (((((carry_6_tmp_8c14f_22)
                    + ((M31_2) * (combination_limb_7_col89)))
                    - (combination_limb_7_col100))
                    - ((p_coef_col103) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_24 = ((((carry_7_tmp_8c14f_23)
                    + ((M31_2) * (combination_limb_8_col90)))
                    - (combination_limb_8_col101))
                    * (M31_16));
                let linear_combination_n_1_coefs_2_output_tmp_8c14f_34 = combination_tmp_8c14f_14;

                let poseidon_partial_round_output_tmp_8c14f_35 = [
                    cube_252_output_tmp_8c14f_1,
                    linear_combination_n_1_coefs_2_output_tmp_8c14f_34,
                ];

                // Poseidon Partial Round.

                *sub_component_inputs.cube_252[1] = poseidon_partial_round_output_tmp_8c14f_35[1];
                let cube_252_output_tmp_8c14f_36 =
                    PackedCube252::deduce_output(poseidon_partial_round_output_tmp_8c14f_35[1]);
                let cube_252_output_limb_0_col104 = cube_252_output_tmp_8c14f_36.get_m31(0);
                *row[104] = cube_252_output_limb_0_col104;
                let cube_252_output_limb_1_col105 = cube_252_output_tmp_8c14f_36.get_m31(1);
                *row[105] = cube_252_output_limb_1_col105;
                let cube_252_output_limb_2_col106 = cube_252_output_tmp_8c14f_36.get_m31(2);
                *row[106] = cube_252_output_limb_2_col106;
                let cube_252_output_limb_3_col107 = cube_252_output_tmp_8c14f_36.get_m31(3);
                *row[107] = cube_252_output_limb_3_col107;
                let cube_252_output_limb_4_col108 = cube_252_output_tmp_8c14f_36.get_m31(4);
                *row[108] = cube_252_output_limb_4_col108;
                let cube_252_output_limb_5_col109 = cube_252_output_tmp_8c14f_36.get_m31(5);
                *row[109] = cube_252_output_limb_5_col109;
                let cube_252_output_limb_6_col110 = cube_252_output_tmp_8c14f_36.get_m31(6);
                *row[110] = cube_252_output_limb_6_col110;
                let cube_252_output_limb_7_col111 = cube_252_output_tmp_8c14f_36.get_m31(7);
                *row[111] = cube_252_output_limb_7_col111;
                let cube_252_output_limb_8_col112 = cube_252_output_tmp_8c14f_36.get_m31(8);
                *row[112] = cube_252_output_limb_8_col112;
                let cube_252_output_limb_9_col113 = cube_252_output_tmp_8c14f_36.get_m31(9);
                *row[113] = cube_252_output_limb_9_col113;
                *lookup_data.cube_252_6 = [
                    M31_1987997202,
                    combination_limb_0_col93,
                    combination_limb_1_col94,
                    combination_limb_2_col95,
                    combination_limb_3_col96,
                    combination_limb_4_col97,
                    combination_limb_5_col98,
                    combination_limb_6_col99,
                    combination_limb_7_col100,
                    combination_limb_8_col101,
                    combination_limb_9_col102,
                    cube_252_output_limb_0_col104,
                    cube_252_output_limb_1_col105,
                    cube_252_output_limb_2_col106,
                    cube_252_output_limb_3_col107,
                    cube_252_output_limb_4_col108,
                    cube_252_output_limb_5_col109,
                    cube_252_output_limb_6_col110,
                    cube_252_output_limb_7_col111,
                    cube_252_output_limb_8_col112,
                    cube_252_output_limb_9_col113,
                ];

                // Linear Combination N 6 Coefs 4 2 3 1 M 1 1.

                let combination_tmp_8c14f_37 = PackedFelt252Width27::from_packed_felt252(
                    (((((((Felt252_0_0_0_0)
                        + ((Felt252_4_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[2],
                            ))))
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_3_partial_rounds_chain_input.2[3],
                            ))))
                        + ((Felt252_3_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_35[0],
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_35[1],
                            ))))
                        - ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_8c14f_36,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_8c14f_0[1],
                            )))),
                );
                let combination_limb_0_col114 = combination_tmp_8c14f_37.get_m31(0);
                *row[114] = combination_limb_0_col114;
                let combination_limb_1_col115 = combination_tmp_8c14f_37.get_m31(1);
                *row[115] = combination_limb_1_col115;
                let combination_limb_2_col116 = combination_tmp_8c14f_37.get_m31(2);
                *row[116] = combination_limb_2_col116;
                let combination_limb_3_col117 = combination_tmp_8c14f_37.get_m31(3);
                *row[117] = combination_limb_3_col117;
                let combination_limb_4_col118 = combination_tmp_8c14f_37.get_m31(4);
                *row[118] = combination_limb_4_col118;
                let combination_limb_5_col119 = combination_tmp_8c14f_37.get_m31(5);
                *row[119] = combination_limb_5_col119;
                let combination_limb_6_col120 = combination_tmp_8c14f_37.get_m31(6);
                *row[120] = combination_limb_6_col120;
                let combination_limb_7_col121 = combination_tmp_8c14f_37.get_m31(7);
                *row[121] = combination_limb_7_col121;
                let combination_limb_8_col122 = combination_tmp_8c14f_37.get_m31(8);
                *row[122] = combination_limb_8_col122;
                let combination_limb_9_col123 = combination_tmp_8c14f_37.get_m31(9);
                *row[123] = combination_limb_9_col123;
                let biased_limb_accumulator_u32_tmp_8c14f_38 = PackedUInt32::from_m31(
                    (((((((((M31_4) * (input_limb_22_col22))
                        + ((M31_2) * (input_limb_32_col32)))
                        + ((M31_3) * (cube_252_output_limb_0_col72)))
                        + (combination_limb_0_col93))
                        - (cube_252_output_limb_0_col104))
                        + (poseidon_round_keys_output_limb_10_col52))
                        - (combination_limb_0_col114))
                        + (M31_268435458)),
                );
                let p_coef_col124 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_38.low().as_m31()) - (M31_2));
                *row[124] = p_coef_col124;
                let carry_0_tmp_8c14f_39 = ((((((((((M31_4) * (input_limb_22_col22))
                    + ((M31_2) * (input_limb_32_col32)))
                    + ((M31_3) * (cube_252_output_limb_0_col72)))
                    + (combination_limb_0_col93))
                    - (cube_252_output_limb_0_col104))
                    + (poseidon_round_keys_output_limb_10_col52))
                    - (combination_limb_0_col114))
                    - (p_coef_col124))
                    * (M31_16));
                let carry_1_tmp_8c14f_40 = (((((((((carry_0_tmp_8c14f_39)
                    + ((M31_4) * (input_limb_23_col23)))
                    + ((M31_2) * (input_limb_33_col33)))
                    + ((M31_3) * (cube_252_output_limb_1_col73)))
                    + (combination_limb_1_col94))
                    - (cube_252_output_limb_1_col105))
                    + (poseidon_round_keys_output_limb_11_col53))
                    - (combination_limb_1_col115))
                    * (M31_16));
                let carry_2_tmp_8c14f_41 = (((((((((carry_1_tmp_8c14f_40)
                    + ((M31_4) * (input_limb_24_col24)))
                    + ((M31_2) * (input_limb_34_col34)))
                    + ((M31_3) * (cube_252_output_limb_2_col74)))
                    + (combination_limb_2_col95))
                    - (cube_252_output_limb_2_col106))
                    + (poseidon_round_keys_output_limb_12_col54))
                    - (combination_limb_2_col116))
                    * (M31_16));
                let carry_3_tmp_8c14f_42 = (((((((((carry_2_tmp_8c14f_41)
                    + ((M31_4) * (input_limb_25_col25)))
                    + ((M31_2) * (input_limb_35_col35)))
                    + ((M31_3) * (cube_252_output_limb_3_col75)))
                    + (combination_limb_3_col96))
                    - (cube_252_output_limb_3_col107))
                    + (poseidon_round_keys_output_limb_13_col55))
                    - (combination_limb_3_col117))
                    * (M31_16));
                let carry_4_tmp_8c14f_43 = (((((((((carry_3_tmp_8c14f_42)
                    + ((M31_4) * (input_limb_26_col26)))
                    + ((M31_2) * (input_limb_36_col36)))
                    + ((M31_3) * (cube_252_output_limb_4_col76)))
                    + (combination_limb_4_col97))
                    - (cube_252_output_limb_4_col108))
                    + (poseidon_round_keys_output_limb_14_col56))
                    - (combination_limb_4_col118))
                    * (M31_16));
                let carry_5_tmp_8c14f_44 = (((((((((carry_4_tmp_8c14f_43)
                    + ((M31_4) * (input_limb_27_col27)))
                    + ((M31_2) * (input_limb_37_col37)))
                    + ((M31_3) * (cube_252_output_limb_5_col77)))
                    + (combination_limb_5_col98))
                    - (cube_252_output_limb_5_col109))
                    + (poseidon_round_keys_output_limb_15_col57))
                    - (combination_limb_5_col119))
                    * (M31_16));
                let carry_6_tmp_8c14f_45 = (((((((((carry_5_tmp_8c14f_44)
                    + ((M31_4) * (input_limb_28_col28)))
                    + ((M31_2) * (input_limb_38_col38)))
                    + ((M31_3) * (cube_252_output_limb_6_col78)))
                    + (combination_limb_6_col99))
                    - (cube_252_output_limb_6_col110))
                    + (poseidon_round_keys_output_limb_16_col58))
                    - (combination_limb_6_col120))
                    * (M31_16));
                let carry_7_tmp_8c14f_46 = ((((((((((carry_6_tmp_8c14f_45)
                    + ((M31_4) * (input_limb_29_col29)))
                    + ((M31_2) * (input_limb_39_col39)))
                    + ((M31_3) * (cube_252_output_limb_7_col79)))
                    + (combination_limb_7_col100))
                    - (cube_252_output_limb_7_col111))
                    + (poseidon_round_keys_output_limb_17_col59))
                    - (combination_limb_7_col121))
                    - ((p_coef_col124) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_47 = (((((((((carry_7_tmp_8c14f_46)
                    + ((M31_4) * (input_limb_30_col30)))
                    + ((M31_2) * (input_limb_40_col40)))
                    + ((M31_3) * (cube_252_output_limb_8_col80)))
                    + (combination_limb_8_col101))
                    - (cube_252_output_limb_8_col112))
                    + (poseidon_round_keys_output_limb_18_col60))
                    - (combination_limb_8_col122))
                    * (M31_16));
                *sub_component_inputs.range_check_4_4_4_4[2] = [
                    ((p_coef_col124) + (M31_2)),
                    ((carry_0_tmp_8c14f_39) + (M31_2)),
                    ((carry_1_tmp_8c14f_40) + (M31_2)),
                    ((carry_2_tmp_8c14f_41) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_7 = [
                    M31_1027333874,
                    ((p_coef_col124) + (M31_2)),
                    ((carry_0_tmp_8c14f_39) + (M31_2)),
                    ((carry_1_tmp_8c14f_40) + (M31_2)),
                    ((carry_2_tmp_8c14f_41) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4_4_4[3] = [
                    ((carry_3_tmp_8c14f_42) + (M31_2)),
                    ((carry_4_tmp_8c14f_43) + (M31_2)),
                    ((carry_5_tmp_8c14f_44) + (M31_2)),
                    ((carry_6_tmp_8c14f_45) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_8 = [
                    M31_1027333874,
                    ((carry_3_tmp_8c14f_42) + (M31_2)),
                    ((carry_4_tmp_8c14f_43) + (M31_2)),
                    ((carry_5_tmp_8c14f_44) + (M31_2)),
                    ((carry_6_tmp_8c14f_45) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4[1] = [
                    ((carry_7_tmp_8c14f_46) + (M31_2)),
                    ((carry_8_tmp_8c14f_47) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_9 = [
                    M31_1651211826,
                    ((carry_7_tmp_8c14f_46) + (M31_2)),
                    ((carry_8_tmp_8c14f_47) + (M31_2)),
                ];
                let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48 =
                    combination_tmp_8c14f_37;

                *sub_component_inputs.range_check_252_width_27[1] =
                    linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48;
                *lookup_data.range_check_252_width_27_10 = [
                    M31_1090315331,
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

                // Linear Combination N 1 Coefs 2.

                let combination_tmp_8c14f_49 = PackedFelt252Width27::from_packed_felt252(
                    ((Felt252_0_0_0_0)
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48,
                            )))),
                );
                let combination_limb_0_col125 = combination_tmp_8c14f_49.get_m31(0);
                *row[125] = combination_limb_0_col125;
                let combination_limb_1_col126 = combination_tmp_8c14f_49.get_m31(1);
                *row[126] = combination_limb_1_col126;
                let combination_limb_2_col127 = combination_tmp_8c14f_49.get_m31(2);
                *row[127] = combination_limb_2_col127;
                let combination_limb_3_col128 = combination_tmp_8c14f_49.get_m31(3);
                *row[128] = combination_limb_3_col128;
                let combination_limb_4_col129 = combination_tmp_8c14f_49.get_m31(4);
                *row[129] = combination_limb_4_col129;
                let combination_limb_5_col130 = combination_tmp_8c14f_49.get_m31(5);
                *row[130] = combination_limb_5_col130;
                let combination_limb_6_col131 = combination_tmp_8c14f_49.get_m31(6);
                *row[131] = combination_limb_6_col131;
                let combination_limb_7_col132 = combination_tmp_8c14f_49.get_m31(7);
                *row[132] = combination_limb_7_col132;
                let combination_limb_8_col133 = combination_tmp_8c14f_49.get_m31(8);
                *row[133] = combination_limb_8_col133;
                let combination_limb_9_col134 = combination_tmp_8c14f_49.get_m31(9);
                *row[134] = combination_limb_9_col134;
                let biased_limb_accumulator_u32_tmp_8c14f_50 = PackedUInt32::from_m31(
                    ((((M31_2) * (combination_limb_0_col114)) - (combination_limb_0_col125))
                        + (M31_134217729)),
                );
                let p_coef_col135 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_50.low().as_m31()) - (M31_1));
                *row[135] = p_coef_col135;
                let carry_0_tmp_8c14f_51 = (((((M31_2) * (combination_limb_0_col114))
                    - (combination_limb_0_col125))
                    - (p_coef_col135))
                    * (M31_16));
                let carry_1_tmp_8c14f_52 = ((((carry_0_tmp_8c14f_51)
                    + ((M31_2) * (combination_limb_1_col115)))
                    - (combination_limb_1_col126))
                    * (M31_16));
                let carry_2_tmp_8c14f_53 = ((((carry_1_tmp_8c14f_52)
                    + ((M31_2) * (combination_limb_2_col116)))
                    - (combination_limb_2_col127))
                    * (M31_16));
                let carry_3_tmp_8c14f_54 = ((((carry_2_tmp_8c14f_53)
                    + ((M31_2) * (combination_limb_3_col117)))
                    - (combination_limb_3_col128))
                    * (M31_16));
                let carry_4_tmp_8c14f_55 = ((((carry_3_tmp_8c14f_54)
                    + ((M31_2) * (combination_limb_4_col118)))
                    - (combination_limb_4_col129))
                    * (M31_16));
                let carry_5_tmp_8c14f_56 = ((((carry_4_tmp_8c14f_55)
                    + ((M31_2) * (combination_limb_5_col119)))
                    - (combination_limb_5_col130))
                    * (M31_16));
                let carry_6_tmp_8c14f_57 = ((((carry_5_tmp_8c14f_56)
                    + ((M31_2) * (combination_limb_6_col120)))
                    - (combination_limb_6_col131))
                    * (M31_16));
                let carry_7_tmp_8c14f_58 = (((((carry_6_tmp_8c14f_57)
                    + ((M31_2) * (combination_limb_7_col121)))
                    - (combination_limb_7_col132))
                    - ((p_coef_col135) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_59 = ((((carry_7_tmp_8c14f_58)
                    + ((M31_2) * (combination_limb_8_col122)))
                    - (combination_limb_8_col133))
                    * (M31_16));
                let linear_combination_n_1_coefs_2_output_tmp_8c14f_69 = combination_tmp_8c14f_49;

                let poseidon_partial_round_output_tmp_8c14f_70 = [
                    cube_252_output_tmp_8c14f_36,
                    linear_combination_n_1_coefs_2_output_tmp_8c14f_69,
                ];

                // Poseidon Partial Round.

                *sub_component_inputs.cube_252[2] = poseidon_partial_round_output_tmp_8c14f_70[1];
                let cube_252_output_tmp_8c14f_71 =
                    PackedCube252::deduce_output(poseidon_partial_round_output_tmp_8c14f_70[1]);
                let cube_252_output_limb_0_col136 = cube_252_output_tmp_8c14f_71.get_m31(0);
                *row[136] = cube_252_output_limb_0_col136;
                let cube_252_output_limb_1_col137 = cube_252_output_tmp_8c14f_71.get_m31(1);
                *row[137] = cube_252_output_limb_1_col137;
                let cube_252_output_limb_2_col138 = cube_252_output_tmp_8c14f_71.get_m31(2);
                *row[138] = cube_252_output_limb_2_col138;
                let cube_252_output_limb_3_col139 = cube_252_output_tmp_8c14f_71.get_m31(3);
                *row[139] = cube_252_output_limb_3_col139;
                let cube_252_output_limb_4_col140 = cube_252_output_tmp_8c14f_71.get_m31(4);
                *row[140] = cube_252_output_limb_4_col140;
                let cube_252_output_limb_5_col141 = cube_252_output_tmp_8c14f_71.get_m31(5);
                *row[141] = cube_252_output_limb_5_col141;
                let cube_252_output_limb_6_col142 = cube_252_output_tmp_8c14f_71.get_m31(6);
                *row[142] = cube_252_output_limb_6_col142;
                let cube_252_output_limb_7_col143 = cube_252_output_tmp_8c14f_71.get_m31(7);
                *row[143] = cube_252_output_limb_7_col143;
                let cube_252_output_limb_8_col144 = cube_252_output_tmp_8c14f_71.get_m31(8);
                *row[144] = cube_252_output_limb_8_col144;
                let cube_252_output_limb_9_col145 = cube_252_output_tmp_8c14f_71.get_m31(9);
                *row[145] = cube_252_output_limb_9_col145;
                *lookup_data.cube_252_11 = [
                    M31_1987997202,
                    combination_limb_0_col125,
                    combination_limb_1_col126,
                    combination_limb_2_col127,
                    combination_limb_3_col128,
                    combination_limb_4_col129,
                    combination_limb_5_col130,
                    combination_limb_6_col131,
                    combination_limb_7_col132,
                    combination_limb_8_col133,
                    combination_limb_9_col134,
                    cube_252_output_limb_0_col136,
                    cube_252_output_limb_1_col137,
                    cube_252_output_limb_2_col138,
                    cube_252_output_limb_3_col139,
                    cube_252_output_limb_4_col140,
                    cube_252_output_limb_5_col141,
                    cube_252_output_limb_6_col142,
                    cube_252_output_limb_7_col143,
                    cube_252_output_limb_8_col144,
                    cube_252_output_limb_9_col145,
                ];

                // Linear Combination N 6 Coefs 4 2 3 1 M 1 1.

                let combination_tmp_8c14f_72 = PackedFelt252Width27::from_packed_felt252(
                    (((((((Felt252_0_0_0_0)
                        + ((Felt252_4_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_35[0],
                            ))))
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_35[1],
                            ))))
                        + ((Felt252_3_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_70[0],
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_partial_round_output_tmp_8c14f_70[1],
                            ))))
                        - ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                cube_252_output_tmp_8c14f_71,
                            ))))
                        + ((Felt252_1_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                poseidon_round_keys_output_tmp_8c14f_0[2],
                            )))),
                );
                let combination_limb_0_col146 = combination_tmp_8c14f_72.get_m31(0);
                *row[146] = combination_limb_0_col146;
                let combination_limb_1_col147 = combination_tmp_8c14f_72.get_m31(1);
                *row[147] = combination_limb_1_col147;
                let combination_limb_2_col148 = combination_tmp_8c14f_72.get_m31(2);
                *row[148] = combination_limb_2_col148;
                let combination_limb_3_col149 = combination_tmp_8c14f_72.get_m31(3);
                *row[149] = combination_limb_3_col149;
                let combination_limb_4_col150 = combination_tmp_8c14f_72.get_m31(4);
                *row[150] = combination_limb_4_col150;
                let combination_limb_5_col151 = combination_tmp_8c14f_72.get_m31(5);
                *row[151] = combination_limb_5_col151;
                let combination_limb_6_col152 = combination_tmp_8c14f_72.get_m31(6);
                *row[152] = combination_limb_6_col152;
                let combination_limb_7_col153 = combination_tmp_8c14f_72.get_m31(7);
                *row[153] = combination_limb_7_col153;
                let combination_limb_8_col154 = combination_tmp_8c14f_72.get_m31(8);
                *row[154] = combination_limb_8_col154;
                let combination_limb_9_col155 = combination_tmp_8c14f_72.get_m31(9);
                *row[155] = combination_limb_9_col155;
                let biased_limb_accumulator_u32_tmp_8c14f_73 = PackedUInt32::from_m31(
                    (((((((((M31_4) * (cube_252_output_limb_0_col72))
                        + ((M31_2) * (combination_limb_0_col93)))
                        + ((M31_3) * (cube_252_output_limb_0_col104)))
                        + (combination_limb_0_col125))
                        - (cube_252_output_limb_0_col136))
                        + (poseidon_round_keys_output_limb_20_col62))
                        - (combination_limb_0_col146))
                        + (M31_268435458)),
                );
                let p_coef_col156 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_73.low().as_m31()) - (M31_2));
                *row[156] = p_coef_col156;
                let carry_0_tmp_8c14f_74 = ((((((((((M31_4)
                    * (cube_252_output_limb_0_col72))
                    + ((M31_2) * (combination_limb_0_col93)))
                    + ((M31_3) * (cube_252_output_limb_0_col104)))
                    + (combination_limb_0_col125))
                    - (cube_252_output_limb_0_col136))
                    + (poseidon_round_keys_output_limb_20_col62))
                    - (combination_limb_0_col146))
                    - (p_coef_col156))
                    * (M31_16));
                let carry_1_tmp_8c14f_75 = (((((((((carry_0_tmp_8c14f_74)
                    + ((M31_4) * (cube_252_output_limb_1_col73)))
                    + ((M31_2) * (combination_limb_1_col94)))
                    + ((M31_3) * (cube_252_output_limb_1_col105)))
                    + (combination_limb_1_col126))
                    - (cube_252_output_limb_1_col137))
                    + (poseidon_round_keys_output_limb_21_col63))
                    - (combination_limb_1_col147))
                    * (M31_16));
                let carry_2_tmp_8c14f_76 = (((((((((carry_1_tmp_8c14f_75)
                    + ((M31_4) * (cube_252_output_limb_2_col74)))
                    + ((M31_2) * (combination_limb_2_col95)))
                    + ((M31_3) * (cube_252_output_limb_2_col106)))
                    + (combination_limb_2_col127))
                    - (cube_252_output_limb_2_col138))
                    + (poseidon_round_keys_output_limb_22_col64))
                    - (combination_limb_2_col148))
                    * (M31_16));
                let carry_3_tmp_8c14f_77 = (((((((((carry_2_tmp_8c14f_76)
                    + ((M31_4) * (cube_252_output_limb_3_col75)))
                    + ((M31_2) * (combination_limb_3_col96)))
                    + ((M31_3) * (cube_252_output_limb_3_col107)))
                    + (combination_limb_3_col128))
                    - (cube_252_output_limb_3_col139))
                    + (poseidon_round_keys_output_limb_23_col65))
                    - (combination_limb_3_col149))
                    * (M31_16));
                let carry_4_tmp_8c14f_78 = (((((((((carry_3_tmp_8c14f_77)
                    + ((M31_4) * (cube_252_output_limb_4_col76)))
                    + ((M31_2) * (combination_limb_4_col97)))
                    + ((M31_3) * (cube_252_output_limb_4_col108)))
                    + (combination_limb_4_col129))
                    - (cube_252_output_limb_4_col140))
                    + (poseidon_round_keys_output_limb_24_col66))
                    - (combination_limb_4_col150))
                    * (M31_16));
                let carry_5_tmp_8c14f_79 = (((((((((carry_4_tmp_8c14f_78)
                    + ((M31_4) * (cube_252_output_limb_5_col77)))
                    + ((M31_2) * (combination_limb_5_col98)))
                    + ((M31_3) * (cube_252_output_limb_5_col109)))
                    + (combination_limb_5_col130))
                    - (cube_252_output_limb_5_col141))
                    + (poseidon_round_keys_output_limb_25_col67))
                    - (combination_limb_5_col151))
                    * (M31_16));
                let carry_6_tmp_8c14f_80 = (((((((((carry_5_tmp_8c14f_79)
                    + ((M31_4) * (cube_252_output_limb_6_col78)))
                    + ((M31_2) * (combination_limb_6_col99)))
                    + ((M31_3) * (cube_252_output_limb_6_col110)))
                    + (combination_limb_6_col131))
                    - (cube_252_output_limb_6_col142))
                    + (poseidon_round_keys_output_limb_26_col68))
                    - (combination_limb_6_col152))
                    * (M31_16));
                let carry_7_tmp_8c14f_81 = ((((((((((carry_6_tmp_8c14f_80)
                    + ((M31_4) * (cube_252_output_limb_7_col79)))
                    + ((M31_2) * (combination_limb_7_col100)))
                    + ((M31_3) * (cube_252_output_limb_7_col111)))
                    + (combination_limb_7_col132))
                    - (cube_252_output_limb_7_col143))
                    + (poseidon_round_keys_output_limb_27_col69))
                    - (combination_limb_7_col153))
                    - ((p_coef_col156) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_82 = (((((((((carry_7_tmp_8c14f_81)
                    + ((M31_4) * (cube_252_output_limb_8_col80)))
                    + ((M31_2) * (combination_limb_8_col101)))
                    + ((M31_3) * (cube_252_output_limb_8_col112)))
                    + (combination_limb_8_col133))
                    - (cube_252_output_limb_8_col144))
                    + (poseidon_round_keys_output_limb_28_col70))
                    - (combination_limb_8_col154))
                    * (M31_16));
                *sub_component_inputs.range_check_4_4_4_4[4] = [
                    ((p_coef_col156) + (M31_2)),
                    ((carry_0_tmp_8c14f_74) + (M31_2)),
                    ((carry_1_tmp_8c14f_75) + (M31_2)),
                    ((carry_2_tmp_8c14f_76) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_12 = [
                    M31_1027333874,
                    ((p_coef_col156) + (M31_2)),
                    ((carry_0_tmp_8c14f_74) + (M31_2)),
                    ((carry_1_tmp_8c14f_75) + (M31_2)),
                    ((carry_2_tmp_8c14f_76) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4_4_4[5] = [
                    ((carry_3_tmp_8c14f_77) + (M31_2)),
                    ((carry_4_tmp_8c14f_78) + (M31_2)),
                    ((carry_5_tmp_8c14f_79) + (M31_2)),
                    ((carry_6_tmp_8c14f_80) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_4_4_13 = [
                    M31_1027333874,
                    ((carry_3_tmp_8c14f_77) + (M31_2)),
                    ((carry_4_tmp_8c14f_78) + (M31_2)),
                    ((carry_5_tmp_8c14f_79) + (M31_2)),
                    ((carry_6_tmp_8c14f_80) + (M31_2)),
                ];
                *sub_component_inputs.range_check_4_4[2] = [
                    ((carry_7_tmp_8c14f_81) + (M31_2)),
                    ((carry_8_tmp_8c14f_82) + (M31_2)),
                ];
                *lookup_data.range_check_4_4_14 = [
                    M31_1651211826,
                    ((carry_7_tmp_8c14f_81) + (M31_2)),
                    ((carry_8_tmp_8c14f_82) + (M31_2)),
                ];
                let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83 =
                    combination_tmp_8c14f_72;

                *sub_component_inputs.range_check_252_width_27[2] =
                    linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83;
                *lookup_data.range_check_252_width_27_15 = [
                    M31_1090315331,
                    combination_limb_0_col146,
                    combination_limb_1_col147,
                    combination_limb_2_col148,
                    combination_limb_3_col149,
                    combination_limb_4_col150,
                    combination_limb_5_col151,
                    combination_limb_6_col152,
                    combination_limb_7_col153,
                    combination_limb_8_col154,
                    combination_limb_9_col155,
                ];

                // Linear Combination N 1 Coefs 2.

                let combination_tmp_8c14f_84 = PackedFelt252Width27::from_packed_felt252(
                    ((Felt252_0_0_0_0)
                        + ((Felt252_2_0_0_0)
                            * (PackedFelt252::from_packed_felt252width27(
                                linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83,
                            )))),
                );
                let combination_limb_0_col157 = combination_tmp_8c14f_84.get_m31(0);
                *row[157] = combination_limb_0_col157;
                let combination_limb_1_col158 = combination_tmp_8c14f_84.get_m31(1);
                *row[158] = combination_limb_1_col158;
                let combination_limb_2_col159 = combination_tmp_8c14f_84.get_m31(2);
                *row[159] = combination_limb_2_col159;
                let combination_limb_3_col160 = combination_tmp_8c14f_84.get_m31(3);
                *row[160] = combination_limb_3_col160;
                let combination_limb_4_col161 = combination_tmp_8c14f_84.get_m31(4);
                *row[161] = combination_limb_4_col161;
                let combination_limb_5_col162 = combination_tmp_8c14f_84.get_m31(5);
                *row[162] = combination_limb_5_col162;
                let combination_limb_6_col163 = combination_tmp_8c14f_84.get_m31(6);
                *row[163] = combination_limb_6_col163;
                let combination_limb_7_col164 = combination_tmp_8c14f_84.get_m31(7);
                *row[164] = combination_limb_7_col164;
                let combination_limb_8_col165 = combination_tmp_8c14f_84.get_m31(8);
                *row[165] = combination_limb_8_col165;
                let combination_limb_9_col166 = combination_tmp_8c14f_84.get_m31(9);
                *row[166] = combination_limb_9_col166;
                let biased_limb_accumulator_u32_tmp_8c14f_85 = PackedUInt32::from_m31(
                    ((((M31_2) * (combination_limb_0_col146)) - (combination_limb_0_col157))
                        + (M31_134217729)),
                );
                let p_coef_col167 =
                    ((biased_limb_accumulator_u32_tmp_8c14f_85.low().as_m31()) - (M31_1));
                *row[167] = p_coef_col167;
                let carry_0_tmp_8c14f_86 = (((((M31_2) * (combination_limb_0_col146))
                    - (combination_limb_0_col157))
                    - (p_coef_col167))
                    * (M31_16));
                let carry_1_tmp_8c14f_87 = ((((carry_0_tmp_8c14f_86)
                    + ((M31_2) * (combination_limb_1_col147)))
                    - (combination_limb_1_col158))
                    * (M31_16));
                let carry_2_tmp_8c14f_88 = ((((carry_1_tmp_8c14f_87)
                    + ((M31_2) * (combination_limb_2_col148)))
                    - (combination_limb_2_col159))
                    * (M31_16));
                let carry_3_tmp_8c14f_89 = ((((carry_2_tmp_8c14f_88)
                    + ((M31_2) * (combination_limb_3_col149)))
                    - (combination_limb_3_col160))
                    * (M31_16));
                let carry_4_tmp_8c14f_90 = ((((carry_3_tmp_8c14f_89)
                    + ((M31_2) * (combination_limb_4_col150)))
                    - (combination_limb_4_col161))
                    * (M31_16));
                let carry_5_tmp_8c14f_91 = ((((carry_4_tmp_8c14f_90)
                    + ((M31_2) * (combination_limb_5_col151)))
                    - (combination_limb_5_col162))
                    * (M31_16));
                let carry_6_tmp_8c14f_92 = ((((carry_5_tmp_8c14f_91)
                    + ((M31_2) * (combination_limb_6_col152)))
                    - (combination_limb_6_col163))
                    * (M31_16));
                let carry_7_tmp_8c14f_93 = (((((carry_6_tmp_8c14f_92)
                    + ((M31_2) * (combination_limb_7_col153)))
                    - (combination_limb_7_col164))
                    - ((p_coef_col167) * (M31_136)))
                    * (M31_16));
                let carry_8_tmp_8c14f_94 = ((((carry_7_tmp_8c14f_93)
                    + ((M31_2) * (combination_limb_8_col154)))
                    - (combination_limb_8_col165))
                    * (M31_16));
                let linear_combination_n_1_coefs_2_output_tmp_8c14f_104 = combination_tmp_8c14f_84;

                let poseidon_partial_round_output_tmp_8c14f_105 = [
                    cube_252_output_tmp_8c14f_71,
                    linear_combination_n_1_coefs_2_output_tmp_8c14f_104,
                ];

                let enabler_col168 = enabler_col.packed_at(row_index);
                *row[168] = enabler_col168;
                *lookup_data.poseidon_3_partial_rounds_chain_16 = [
                    M31_1343313504,
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
                    input_limb_32_col32,
                    input_limb_33_col33,
                    input_limb_34_col34,
                    input_limb_35_col35,
                    input_limb_36_col36,
                    input_limb_37_col37,
                    input_limb_38_col38,
                    input_limb_39_col39,
                    input_limb_40_col40,
                    input_limb_41_col41,
                ];
                *lookup_data.poseidon_3_partial_rounds_chain_17 = [
                    M31_1343313504,
                    input_limb_0_col0,
                    ((input_limb_1_col1) + (M31_1)),
                    cube_252_output_limb_0_col104,
                    cube_252_output_limb_1_col105,
                    cube_252_output_limb_2_col106,
                    cube_252_output_limb_3_col107,
                    cube_252_output_limb_4_col108,
                    cube_252_output_limb_5_col109,
                    cube_252_output_limb_6_col110,
                    cube_252_output_limb_7_col111,
                    cube_252_output_limb_8_col112,
                    cube_252_output_limb_9_col113,
                    combination_limb_0_col125,
                    combination_limb_1_col126,
                    combination_limb_2_col127,
                    combination_limb_3_col128,
                    combination_limb_4_col129,
                    combination_limb_5_col130,
                    combination_limb_6_col131,
                    combination_limb_7_col132,
                    combination_limb_8_col133,
                    combination_limb_9_col134,
                    cube_252_output_limb_0_col136,
                    cube_252_output_limb_1_col137,
                    cube_252_output_limb_2_col138,
                    cube_252_output_limb_3_col139,
                    cube_252_output_limb_4_col140,
                    cube_252_output_limb_5_col141,
                    cube_252_output_limb_6_col142,
                    cube_252_output_limb_7_col143,
                    cube_252_output_limb_8_col144,
                    cube_252_output_limb_9_col145,
                    combination_limb_0_col157,
                    combination_limb_1_col158,
                    combination_limb_2_col159,
                    combination_limb_3_col160,
                    combination_limb_4_col161,
                    combination_limb_5_col162,
                    combination_limb_6_col163,
                    combination_limb_7_col164,
                    combination_limb_8_col165,
                    combination_limb_9_col166,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col168;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `poseidon_3_partial_rounds_chain` — mechanical rewrite
// of `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     poseidon_round_keys_0[32] 0..31
//     cube_252_1[21] 32..52
//     range_check_4_4_4_4_2[5] 53..57
//     range_check_4_4_4_4_3[5] 58..62
//     range_check_4_4_4[3] 63..65
//     range_check_252_width_27_5[11] 66..76
//     cube_252_6[21] 77..97
//     range_check_4_4_4_4_7[5] 98..102
//     range_check_4_4_4_4_8[5] 103..107
//     range_check_4_4_9[3] 108..110
//     range_check_252_width_27_10[11] 111..121
//     cube_252_11[21] 122..142
//     range_check_4_4_4_4_12[5] 143..147
//     range_check_4_4_4_4_13[5] 148..152
//     range_check_4_4_14[3] 153..155
//     range_check_252_width_27_15[11] 156..166
//     poseidon_3_partial_rounds_chain_16[43] 167..209
//     poseidon_3_partial_rounds_chain_17[43] 210..252
//     mults_0 253
//     mults_1 254
//     (255 words)
//   SUB-INPUT words:
//     poseidon_round_keys[0] 0
//     cube_252[0] 1..10
//     cube_252[1] 11..20
//     cube_252[2] 21..30
//     range_check_4_4_4_4[0] 31..34
//     range_check_4_4_4_4[1] 35..38
//     range_check_4_4_4_4[2] 39..42
//     range_check_4_4_4_4[3] 43..46
//     range_check_4_4_4_4[4] 47..50
//     range_check_4_4_4_4[5] 51..54
//     range_check_4_4[0] 55..56
//     range_check_4_4[1] 57..58
//     range_check_4_4[2] 59..60
//     range_check_252_width_27[0] 61..70
//     range_check_252_width_27[1] 71..80
//     range_check_252_width_27[2] 81..90
//     (91 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 255;
pub(crate) const N_SUB_INPUT_WORDS: usize = 91;

/// The per-row `poseidon_3_partial_rounds_chain` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn poseidon_3_partial_rounds_chain_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_4 = eval.m31_const(4);
    let m31_16 = eval.m31_const(16);
    let m31_136 = eval.m31_const(136);
    let m31_512 = eval.m31_const(512);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217729 = eval.m31_const(134217729);
    let m31_268435458 = eval.m31_const(268435458);
    let m31_1024310512 = eval.m31_const(1024310512);
    let m31_1027333874 = eval.m31_const(1027333874);
    let m31_1090315331 = eval.m31_const(1090315331);
    let m31_1343313504 = eval.m31_const(1343313504);
    let m31_1651211826 = eval.m31_const(1651211826);
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
    let wg_v330 = eval.input(32);
    let wg_v331 = eval.input(33);
    let wg_v332 = eval.input(34);
    let wg_v333 = eval.input(35);
    let wg_v334 = eval.input(36);
    let wg_v335 = eval.input(37);
    let wg_v336 = eval.input(38);
    let wg_v337 = eval.input(39);
    let wg_v338 = eval.input(40);
    let wg_v339 = eval.input(41);
    let wg_v340 = [
        wg_v330, wg_v331, wg_v332, wg_v333, wg_v334, wg_v335, wg_v336, wg_v337, wg_v338, wg_v339,
    ];
    let input_limb_32_col32 = wg_v340[0];
    eval.set_col(32, input_limb_32_col32);
    let wg_v341 = eval.input(32);
    let wg_v342 = eval.input(33);
    let wg_v343 = eval.input(34);
    let wg_v344 = eval.input(35);
    let wg_v345 = eval.input(36);
    let wg_v346 = eval.input(37);
    let wg_v347 = eval.input(38);
    let wg_v348 = eval.input(39);
    let wg_v349 = eval.input(40);
    let wg_v350 = eval.input(41);
    let wg_v351 = [
        wg_v341, wg_v342, wg_v343, wg_v344, wg_v345, wg_v346, wg_v347, wg_v348, wg_v349, wg_v350,
    ];
    let input_limb_33_col33 = wg_v351[1];
    eval.set_col(33, input_limb_33_col33);
    let wg_v352 = eval.input(32);
    let wg_v353 = eval.input(33);
    let wg_v354 = eval.input(34);
    let wg_v355 = eval.input(35);
    let wg_v356 = eval.input(36);
    let wg_v357 = eval.input(37);
    let wg_v358 = eval.input(38);
    let wg_v359 = eval.input(39);
    let wg_v360 = eval.input(40);
    let wg_v361 = eval.input(41);
    let wg_v362 = [
        wg_v352, wg_v353, wg_v354, wg_v355, wg_v356, wg_v357, wg_v358, wg_v359, wg_v360, wg_v361,
    ];
    let input_limb_34_col34 = wg_v362[2];
    eval.set_col(34, input_limb_34_col34);
    let wg_v363 = eval.input(32);
    let wg_v364 = eval.input(33);
    let wg_v365 = eval.input(34);
    let wg_v366 = eval.input(35);
    let wg_v367 = eval.input(36);
    let wg_v368 = eval.input(37);
    let wg_v369 = eval.input(38);
    let wg_v370 = eval.input(39);
    let wg_v371 = eval.input(40);
    let wg_v372 = eval.input(41);
    let wg_v373 = [
        wg_v363, wg_v364, wg_v365, wg_v366, wg_v367, wg_v368, wg_v369, wg_v370, wg_v371, wg_v372,
    ];
    let input_limb_35_col35 = wg_v373[3];
    eval.set_col(35, input_limb_35_col35);
    let wg_v374 = eval.input(32);
    let wg_v375 = eval.input(33);
    let wg_v376 = eval.input(34);
    let wg_v377 = eval.input(35);
    let wg_v378 = eval.input(36);
    let wg_v379 = eval.input(37);
    let wg_v380 = eval.input(38);
    let wg_v381 = eval.input(39);
    let wg_v382 = eval.input(40);
    let wg_v383 = eval.input(41);
    let wg_v384 = [
        wg_v374, wg_v375, wg_v376, wg_v377, wg_v378, wg_v379, wg_v380, wg_v381, wg_v382, wg_v383,
    ];
    let input_limb_36_col36 = wg_v384[4];
    eval.set_col(36, input_limb_36_col36);
    let wg_v385 = eval.input(32);
    let wg_v386 = eval.input(33);
    let wg_v387 = eval.input(34);
    let wg_v388 = eval.input(35);
    let wg_v389 = eval.input(36);
    let wg_v390 = eval.input(37);
    let wg_v391 = eval.input(38);
    let wg_v392 = eval.input(39);
    let wg_v393 = eval.input(40);
    let wg_v394 = eval.input(41);
    let wg_v395 = [
        wg_v385, wg_v386, wg_v387, wg_v388, wg_v389, wg_v390, wg_v391, wg_v392, wg_v393, wg_v394,
    ];
    let input_limb_37_col37 = wg_v395[5];
    eval.set_col(37, input_limb_37_col37);
    let wg_v396 = eval.input(32);
    let wg_v397 = eval.input(33);
    let wg_v398 = eval.input(34);
    let wg_v399 = eval.input(35);
    let wg_v400 = eval.input(36);
    let wg_v401 = eval.input(37);
    let wg_v402 = eval.input(38);
    let wg_v403 = eval.input(39);
    let wg_v404 = eval.input(40);
    let wg_v405 = eval.input(41);
    let wg_v406 = [
        wg_v396, wg_v397, wg_v398, wg_v399, wg_v400, wg_v401, wg_v402, wg_v403, wg_v404, wg_v405,
    ];
    let input_limb_38_col38 = wg_v406[6];
    eval.set_col(38, input_limb_38_col38);
    let wg_v407 = eval.input(32);
    let wg_v408 = eval.input(33);
    let wg_v409 = eval.input(34);
    let wg_v410 = eval.input(35);
    let wg_v411 = eval.input(36);
    let wg_v412 = eval.input(37);
    let wg_v413 = eval.input(38);
    let wg_v414 = eval.input(39);
    let wg_v415 = eval.input(40);
    let wg_v416 = eval.input(41);
    let wg_v417 = [
        wg_v407, wg_v408, wg_v409, wg_v410, wg_v411, wg_v412, wg_v413, wg_v414, wg_v415, wg_v416,
    ];
    let input_limb_39_col39 = wg_v417[7];
    eval.set_col(39, input_limb_39_col39);
    let wg_v418 = eval.input(32);
    let wg_v419 = eval.input(33);
    let wg_v420 = eval.input(34);
    let wg_v421 = eval.input(35);
    let wg_v422 = eval.input(36);
    let wg_v423 = eval.input(37);
    let wg_v424 = eval.input(38);
    let wg_v425 = eval.input(39);
    let wg_v426 = eval.input(40);
    let wg_v427 = eval.input(41);
    let wg_v428 = [
        wg_v418, wg_v419, wg_v420, wg_v421, wg_v422, wg_v423, wg_v424, wg_v425, wg_v426, wg_v427,
    ];
    let input_limb_40_col40 = wg_v428[8];
    eval.set_col(40, input_limb_40_col40);
    let wg_v429 = eval.input(32);
    let wg_v430 = eval.input(33);
    let wg_v431 = eval.input(34);
    let wg_v432 = eval.input(35);
    let wg_v433 = eval.input(36);
    let wg_v434 = eval.input(37);
    let wg_v435 = eval.input(38);
    let wg_v436 = eval.input(39);
    let wg_v437 = eval.input(40);
    let wg_v438 = eval.input(41);
    let wg_v439 = [
        wg_v429, wg_v430, wg_v431, wg_v432, wg_v433, wg_v434, wg_v435, wg_v436, wg_v437, wg_v438,
    ];
    let input_limb_41_col41 = wg_v439[9];
    eval.set_col(41, input_limb_41_col41);
    eval.set_sub_input_word(0, input_limb_1_col1);
    let poseidon_round_keys_output_tmp_8c14f_0 = eval.deduce_poseidon_round_keys(input_limb_1_col1);
    let poseidon_round_keys_output_limb_0_col42 = poseidon_round_keys_output_tmp_8c14f_0[0][0];
    eval.set_col(42, poseidon_round_keys_output_limb_0_col42);
    let poseidon_round_keys_output_limb_1_col43 = poseidon_round_keys_output_tmp_8c14f_0[0][1];
    eval.set_col(43, poseidon_round_keys_output_limb_1_col43);
    let poseidon_round_keys_output_limb_2_col44 = poseidon_round_keys_output_tmp_8c14f_0[0][2];
    eval.set_col(44, poseidon_round_keys_output_limb_2_col44);
    let poseidon_round_keys_output_limb_3_col45 = poseidon_round_keys_output_tmp_8c14f_0[0][3];
    eval.set_col(45, poseidon_round_keys_output_limb_3_col45);
    let poseidon_round_keys_output_limb_4_col46 = poseidon_round_keys_output_tmp_8c14f_0[0][4];
    eval.set_col(46, poseidon_round_keys_output_limb_4_col46);
    let poseidon_round_keys_output_limb_5_col47 = poseidon_round_keys_output_tmp_8c14f_0[0][5];
    eval.set_col(47, poseidon_round_keys_output_limb_5_col47);
    let poseidon_round_keys_output_limb_6_col48 = poseidon_round_keys_output_tmp_8c14f_0[0][6];
    eval.set_col(48, poseidon_round_keys_output_limb_6_col48);
    let poseidon_round_keys_output_limb_7_col49 = poseidon_round_keys_output_tmp_8c14f_0[0][7];
    eval.set_col(49, poseidon_round_keys_output_limb_7_col49);
    let poseidon_round_keys_output_limb_8_col50 = poseidon_round_keys_output_tmp_8c14f_0[0][8];
    eval.set_col(50, poseidon_round_keys_output_limb_8_col50);
    let poseidon_round_keys_output_limb_9_col51 = poseidon_round_keys_output_tmp_8c14f_0[0][9];
    eval.set_col(51, poseidon_round_keys_output_limb_9_col51);
    let poseidon_round_keys_output_limb_10_col52 = poseidon_round_keys_output_tmp_8c14f_0[1][0];
    eval.set_col(52, poseidon_round_keys_output_limb_10_col52);
    let poseidon_round_keys_output_limb_11_col53 = poseidon_round_keys_output_tmp_8c14f_0[1][1];
    eval.set_col(53, poseidon_round_keys_output_limb_11_col53);
    let poseidon_round_keys_output_limb_12_col54 = poseidon_round_keys_output_tmp_8c14f_0[1][2];
    eval.set_col(54, poseidon_round_keys_output_limb_12_col54);
    let poseidon_round_keys_output_limb_13_col55 = poseidon_round_keys_output_tmp_8c14f_0[1][3];
    eval.set_col(55, poseidon_round_keys_output_limb_13_col55);
    let poseidon_round_keys_output_limb_14_col56 = poseidon_round_keys_output_tmp_8c14f_0[1][4];
    eval.set_col(56, poseidon_round_keys_output_limb_14_col56);
    let poseidon_round_keys_output_limb_15_col57 = poseidon_round_keys_output_tmp_8c14f_0[1][5];
    eval.set_col(57, poseidon_round_keys_output_limb_15_col57);
    let poseidon_round_keys_output_limb_16_col58 = poseidon_round_keys_output_tmp_8c14f_0[1][6];
    eval.set_col(58, poseidon_round_keys_output_limb_16_col58);
    let poseidon_round_keys_output_limb_17_col59 = poseidon_round_keys_output_tmp_8c14f_0[1][7];
    eval.set_col(59, poseidon_round_keys_output_limb_17_col59);
    let poseidon_round_keys_output_limb_18_col60 = poseidon_round_keys_output_tmp_8c14f_0[1][8];
    eval.set_col(60, poseidon_round_keys_output_limb_18_col60);
    let poseidon_round_keys_output_limb_19_col61 = poseidon_round_keys_output_tmp_8c14f_0[1][9];
    eval.set_col(61, poseidon_round_keys_output_limb_19_col61);
    let poseidon_round_keys_output_limb_20_col62 = poseidon_round_keys_output_tmp_8c14f_0[2][0];
    eval.set_col(62, poseidon_round_keys_output_limb_20_col62);
    let poseidon_round_keys_output_limb_21_col63 = poseidon_round_keys_output_tmp_8c14f_0[2][1];
    eval.set_col(63, poseidon_round_keys_output_limb_21_col63);
    let poseidon_round_keys_output_limb_22_col64 = poseidon_round_keys_output_tmp_8c14f_0[2][2];
    eval.set_col(64, poseidon_round_keys_output_limb_22_col64);
    let poseidon_round_keys_output_limb_23_col65 = poseidon_round_keys_output_tmp_8c14f_0[2][3];
    eval.set_col(65, poseidon_round_keys_output_limb_23_col65);
    let poseidon_round_keys_output_limb_24_col66 = poseidon_round_keys_output_tmp_8c14f_0[2][4];
    eval.set_col(66, poseidon_round_keys_output_limb_24_col66);
    let poseidon_round_keys_output_limb_25_col67 = poseidon_round_keys_output_tmp_8c14f_0[2][5];
    eval.set_col(67, poseidon_round_keys_output_limb_25_col67);
    let poseidon_round_keys_output_limb_26_col68 = poseidon_round_keys_output_tmp_8c14f_0[2][6];
    eval.set_col(68, poseidon_round_keys_output_limb_26_col68);
    let poseidon_round_keys_output_limb_27_col69 = poseidon_round_keys_output_tmp_8c14f_0[2][7];
    eval.set_col(69, poseidon_round_keys_output_limb_27_col69);
    let poseidon_round_keys_output_limb_28_col70 = poseidon_round_keys_output_tmp_8c14f_0[2][8];
    eval.set_col(70, poseidon_round_keys_output_limb_28_col70);
    let poseidon_round_keys_output_limb_29_col71 = poseidon_round_keys_output_tmp_8c14f_0[2][9];
    eval.set_col(71, poseidon_round_keys_output_limb_29_col71);
    eval.set_lookup_word(0, m31_1024310512);
    eval.set_lookup_word(1, input_limb_1_col1);
    eval.set_lookup_word(2, poseidon_round_keys_output_limb_0_col42);
    eval.set_lookup_word(3, poseidon_round_keys_output_limb_1_col43);
    eval.set_lookup_word(4, poseidon_round_keys_output_limb_2_col44);
    eval.set_lookup_word(5, poseidon_round_keys_output_limb_3_col45);
    eval.set_lookup_word(6, poseidon_round_keys_output_limb_4_col46);
    eval.set_lookup_word(7, poseidon_round_keys_output_limb_5_col47);
    eval.set_lookup_word(8, poseidon_round_keys_output_limb_6_col48);
    eval.set_lookup_word(9, poseidon_round_keys_output_limb_7_col49);
    eval.set_lookup_word(10, poseidon_round_keys_output_limb_8_col50);
    eval.set_lookup_word(11, poseidon_round_keys_output_limb_9_col51);
    eval.set_lookup_word(12, poseidon_round_keys_output_limb_10_col52);
    eval.set_lookup_word(13, poseidon_round_keys_output_limb_11_col53);
    eval.set_lookup_word(14, poseidon_round_keys_output_limb_12_col54);
    eval.set_lookup_word(15, poseidon_round_keys_output_limb_13_col55);
    eval.set_lookup_word(16, poseidon_round_keys_output_limb_14_col56);
    eval.set_lookup_word(17, poseidon_round_keys_output_limb_15_col57);
    eval.set_lookup_word(18, poseidon_round_keys_output_limb_16_col58);
    eval.set_lookup_word(19, poseidon_round_keys_output_limb_17_col59);
    eval.set_lookup_word(20, poseidon_round_keys_output_limb_18_col60);
    eval.set_lookup_word(21, poseidon_round_keys_output_limb_19_col61);
    eval.set_lookup_word(22, poseidon_round_keys_output_limb_20_col62);
    eval.set_lookup_word(23, poseidon_round_keys_output_limb_21_col63);
    eval.set_lookup_word(24, poseidon_round_keys_output_limb_22_col64);
    eval.set_lookup_word(25, poseidon_round_keys_output_limb_23_col65);
    eval.set_lookup_word(26, poseidon_round_keys_output_limb_24_col66);
    eval.set_lookup_word(27, poseidon_round_keys_output_limb_25_col67);
    eval.set_lookup_word(28, poseidon_round_keys_output_limb_26_col68);
    eval.set_lookup_word(29, poseidon_round_keys_output_limb_27_col69);
    eval.set_lookup_word(30, poseidon_round_keys_output_limb_28_col70);
    eval.set_lookup_word(31, poseidon_round_keys_output_limb_29_col71);
    let wg_v440 = eval.input(32);
    let wg_v441 = eval.input(33);
    let wg_v442 = eval.input(34);
    let wg_v443 = eval.input(35);
    let wg_v444 = eval.input(36);
    let wg_v445 = eval.input(37);
    let wg_v446 = eval.input(38);
    let wg_v447 = eval.input(39);
    let wg_v448 = eval.input(40);
    let wg_v449 = eval.input(41);
    let wg_v450 = [
        wg_v440, wg_v441, wg_v442, wg_v443, wg_v444, wg_v445, wg_v446, wg_v447, wg_v448, wg_v449,
    ];
    let wg_v451 = wg_v450;
    let wg_v452 = wg_v451[0];
    let wg_v453 = wg_v451[1];
    let wg_v454 = wg_v451[2];
    let wg_v455 = wg_v451[3];
    let wg_v456 = wg_v451[4];
    let wg_v457 = wg_v451[5];
    let wg_v458 = wg_v451[6];
    let wg_v459 = wg_v451[7];
    let wg_v460 = wg_v451[8];
    let wg_v461 = wg_v451[9];
    eval.set_sub_input_word(1, wg_v452);
    eval.set_sub_input_word(2, wg_v453);
    eval.set_sub_input_word(3, wg_v454);
    eval.set_sub_input_word(4, wg_v455);
    eval.set_sub_input_word(5, wg_v456);
    eval.set_sub_input_word(6, wg_v457);
    eval.set_sub_input_word(7, wg_v458);
    eval.set_sub_input_word(8, wg_v459);
    eval.set_sub_input_word(9, wg_v460);
    eval.set_sub_input_word(10, wg_v461);
    let wg_v462 = eval.input(32);
    let wg_v463 = eval.input(33);
    let wg_v464 = eval.input(34);
    let wg_v465 = eval.input(35);
    let wg_v466 = eval.input(36);
    let wg_v467 = eval.input(37);
    let wg_v468 = eval.input(38);
    let wg_v469 = eval.input(39);
    let wg_v470 = eval.input(40);
    let wg_v471 = eval.input(41);
    let wg_v472 = [
        wg_v462, wg_v463, wg_v464, wg_v465, wg_v466, wg_v467, wg_v468, wg_v469, wg_v470, wg_v471,
    ];
    let cube_252_output_tmp_8c14f_1 = eval.deduce_cube_252(wg_v472);
    let cube_252_output_limb_0_col72 = cube_252_output_tmp_8c14f_1[0];
    eval.set_col(72, cube_252_output_limb_0_col72);
    let cube_252_output_limb_1_col73 = cube_252_output_tmp_8c14f_1[1];
    eval.set_col(73, cube_252_output_limb_1_col73);
    let cube_252_output_limb_2_col74 = cube_252_output_tmp_8c14f_1[2];
    eval.set_col(74, cube_252_output_limb_2_col74);
    let cube_252_output_limb_3_col75 = cube_252_output_tmp_8c14f_1[3];
    eval.set_col(75, cube_252_output_limb_3_col75);
    let cube_252_output_limb_4_col76 = cube_252_output_tmp_8c14f_1[4];
    eval.set_col(76, cube_252_output_limb_4_col76);
    let cube_252_output_limb_5_col77 = cube_252_output_tmp_8c14f_1[5];
    eval.set_col(77, cube_252_output_limb_5_col77);
    let cube_252_output_limb_6_col78 = cube_252_output_tmp_8c14f_1[6];
    eval.set_col(78, cube_252_output_limb_6_col78);
    let cube_252_output_limb_7_col79 = cube_252_output_tmp_8c14f_1[7];
    eval.set_col(79, cube_252_output_limb_7_col79);
    let cube_252_output_limb_8_col80 = cube_252_output_tmp_8c14f_1[8];
    eval.set_col(80, cube_252_output_limb_8_col80);
    let cube_252_output_limb_9_col81 = cube_252_output_tmp_8c14f_1[9];
    eval.set_col(81, cube_252_output_limb_9_col81);
    eval.set_lookup_word(32, m31_1987997202);
    eval.set_lookup_word(33, input_limb_32_col32);
    eval.set_lookup_word(34, input_limb_33_col33);
    eval.set_lookup_word(35, input_limb_34_col34);
    eval.set_lookup_word(36, input_limb_35_col35);
    eval.set_lookup_word(37, input_limb_36_col36);
    eval.set_lookup_word(38, input_limb_37_col37);
    eval.set_lookup_word(39, input_limb_38_col38);
    eval.set_lookup_word(40, input_limb_39_col39);
    eval.set_lookup_word(41, input_limb_40_col40);
    eval.set_lookup_word(42, input_limb_41_col41);
    eval.set_lookup_word(43, cube_252_output_limb_0_col72);
    eval.set_lookup_word(44, cube_252_output_limb_1_col73);
    eval.set_lookup_word(45, cube_252_output_limb_2_col74);
    eval.set_lookup_word(46, cube_252_output_limb_3_col75);
    eval.set_lookup_word(47, cube_252_output_limb_4_col76);
    eval.set_lookup_word(48, cube_252_output_limb_5_col77);
    eval.set_lookup_word(49, cube_252_output_limb_6_col78);
    eval.set_lookup_word(50, cube_252_output_limb_7_col79);
    eval.set_lookup_word(51, cube_252_output_limb_8_col80);
    eval.set_lookup_word(52, cube_252_output_limb_9_col81);
    let wg_v473 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v474 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v475 = eval.input(2);
    let wg_v476 = eval.input(3);
    let wg_v477 = eval.input(4);
    let wg_v478 = eval.input(5);
    let wg_v479 = eval.input(6);
    let wg_v480 = eval.input(7);
    let wg_v481 = eval.input(8);
    let wg_v482 = eval.input(9);
    let wg_v483 = eval.input(10);
    let wg_v484 = eval.input(11);
    let wg_v485 = [
        wg_v475, wg_v476, wg_v477, wg_v478, wg_v479, wg_v480, wg_v481, wg_v482, wg_v483, wg_v484,
    ];
    let wg_v486 = eval.felt_from_w27_words(wg_v485);
    let wg_v487 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v488 = eval.felt_mul(wg_v487.clone(), wg_v486.clone());
    let wg_v489 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v490 = eval.felt_add(wg_v489.clone(), wg_v488.clone());
    let wg_v491 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v492 = eval.input(12);
    let wg_v493 = eval.input(13);
    let wg_v494 = eval.input(14);
    let wg_v495 = eval.input(15);
    let wg_v496 = eval.input(16);
    let wg_v497 = eval.input(17);
    let wg_v498 = eval.input(18);
    let wg_v499 = eval.input(19);
    let wg_v500 = eval.input(20);
    let wg_v501 = eval.input(21);
    let wg_v502 = [
        wg_v492, wg_v493, wg_v494, wg_v495, wg_v496, wg_v497, wg_v498, wg_v499, wg_v500, wg_v501,
    ];
    let wg_v503 = eval.felt_from_w27_words(wg_v502);
    let wg_v504 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v505 = eval.felt_mul(wg_v504.clone(), wg_v503.clone());
    let wg_v506 = eval.felt_add(wg_v490.clone(), wg_v505.clone());
    let wg_v507 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v508 = eval.input(22);
    let wg_v509 = eval.input(23);
    let wg_v510 = eval.input(24);
    let wg_v511 = eval.input(25);
    let wg_v512 = eval.input(26);
    let wg_v513 = eval.input(27);
    let wg_v514 = eval.input(28);
    let wg_v515 = eval.input(29);
    let wg_v516 = eval.input(30);
    let wg_v517 = eval.input(31);
    let wg_v518 = [
        wg_v508, wg_v509, wg_v510, wg_v511, wg_v512, wg_v513, wg_v514, wg_v515, wg_v516, wg_v517,
    ];
    let wg_v519 = eval.felt_from_w27_words(wg_v518);
    let wg_v520 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v521 = eval.felt_mul(wg_v520.clone(), wg_v519.clone());
    let wg_v522 = eval.felt_add(wg_v506.clone(), wg_v521.clone());
    let wg_v523 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v524 = eval.input(32);
    let wg_v525 = eval.input(33);
    let wg_v526 = eval.input(34);
    let wg_v527 = eval.input(35);
    let wg_v528 = eval.input(36);
    let wg_v529 = eval.input(37);
    let wg_v530 = eval.input(38);
    let wg_v531 = eval.input(39);
    let wg_v532 = eval.input(40);
    let wg_v533 = eval.input(41);
    let wg_v534 = [
        wg_v524, wg_v525, wg_v526, wg_v527, wg_v528, wg_v529, wg_v530, wg_v531, wg_v532, wg_v533,
    ];
    let wg_v535 = eval.felt_from_w27_words(wg_v534);
    let wg_v536 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v537 = eval.felt_mul(wg_v536.clone(), wg_v535.clone());
    let wg_v538 = eval.felt_add(wg_v522.clone(), wg_v537.clone());
    let wg_v539 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v540 = eval.felt_from_w27_words(cube_252_output_tmp_8c14f_1);
    let wg_v541 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v542 = eval.felt_mul(wg_v541.clone(), wg_v540.clone());
    let wg_v543 = eval.felt_sub(wg_v538.clone(), wg_v542.clone());
    let wg_v544 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v545 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_8c14f_0[0]);
    let wg_v546 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v547 = eval.felt_mul(wg_v546.clone(), wg_v545.clone());
    let wg_v548 = eval.felt_add(wg_v543.clone(), wg_v547.clone());
    let wg_v549 = eval.felt_get_m31(&wg_v548, 0);
    let wg_v550 = eval.felt_get_m31(&wg_v548, 1);
    let wg_v551 = eval.m31_mul(wg_v550, m31_512);
    let wg_v552 = eval.m31_add(wg_v549, wg_v551);
    let wg_v553 = eval.felt_get_m31(&wg_v548, 2);
    let wg_v554 = eval.m31_mul(wg_v553, m31_262144);
    let wg_v555 = eval.m31_add(wg_v552, wg_v554);
    let wg_v556 = eval.felt_get_m31(&wg_v548, 3);
    let wg_v557 = eval.felt_get_m31(&wg_v548, 4);
    let wg_v558 = eval.m31_mul(wg_v557, m31_512);
    let wg_v559 = eval.m31_add(wg_v556, wg_v558);
    let wg_v560 = eval.felt_get_m31(&wg_v548, 5);
    let wg_v561 = eval.m31_mul(wg_v560, m31_262144);
    let wg_v562 = eval.m31_add(wg_v559, wg_v561);
    let wg_v563 = eval.felt_get_m31(&wg_v548, 6);
    let wg_v564 = eval.felt_get_m31(&wg_v548, 7);
    let wg_v565 = eval.m31_mul(wg_v564, m31_512);
    let wg_v566 = eval.m31_add(wg_v563, wg_v565);
    let wg_v567 = eval.felt_get_m31(&wg_v548, 8);
    let wg_v568 = eval.m31_mul(wg_v567, m31_262144);
    let wg_v569 = eval.m31_add(wg_v566, wg_v568);
    let wg_v570 = eval.felt_get_m31(&wg_v548, 9);
    let wg_v571 = eval.felt_get_m31(&wg_v548, 10);
    let wg_v572 = eval.m31_mul(wg_v571, m31_512);
    let wg_v573 = eval.m31_add(wg_v570, wg_v572);
    let wg_v574 = eval.felt_get_m31(&wg_v548, 11);
    let wg_v575 = eval.m31_mul(wg_v574, m31_262144);
    let wg_v576 = eval.m31_add(wg_v573, wg_v575);
    let wg_v577 = eval.felt_get_m31(&wg_v548, 12);
    let wg_v578 = eval.felt_get_m31(&wg_v548, 13);
    let wg_v579 = eval.m31_mul(wg_v578, m31_512);
    let wg_v580 = eval.m31_add(wg_v577, wg_v579);
    let wg_v581 = eval.felt_get_m31(&wg_v548, 14);
    let wg_v582 = eval.m31_mul(wg_v581, m31_262144);
    let wg_v583 = eval.m31_add(wg_v580, wg_v582);
    let wg_v584 = eval.felt_get_m31(&wg_v548, 15);
    let wg_v585 = eval.felt_get_m31(&wg_v548, 16);
    let wg_v586 = eval.m31_mul(wg_v585, m31_512);
    let wg_v587 = eval.m31_add(wg_v584, wg_v586);
    let wg_v588 = eval.felt_get_m31(&wg_v548, 17);
    let wg_v589 = eval.m31_mul(wg_v588, m31_262144);
    let wg_v590 = eval.m31_add(wg_v587, wg_v589);
    let wg_v591 = eval.felt_get_m31(&wg_v548, 18);
    let wg_v592 = eval.felt_get_m31(&wg_v548, 19);
    let wg_v593 = eval.m31_mul(wg_v592, m31_512);
    let wg_v594 = eval.m31_add(wg_v591, wg_v593);
    let wg_v595 = eval.felt_get_m31(&wg_v548, 20);
    let wg_v596 = eval.m31_mul(wg_v595, m31_262144);
    let wg_v597 = eval.m31_add(wg_v594, wg_v596);
    let wg_v598 = eval.felt_get_m31(&wg_v548, 21);
    let wg_v599 = eval.felt_get_m31(&wg_v548, 22);
    let wg_v600 = eval.m31_mul(wg_v599, m31_512);
    let wg_v601 = eval.m31_add(wg_v598, wg_v600);
    let wg_v602 = eval.felt_get_m31(&wg_v548, 23);
    let wg_v603 = eval.m31_mul(wg_v602, m31_262144);
    let wg_v604 = eval.m31_add(wg_v601, wg_v603);
    let wg_v605 = eval.felt_get_m31(&wg_v548, 24);
    let wg_v606 = eval.felt_get_m31(&wg_v548, 25);
    let wg_v607 = eval.m31_mul(wg_v606, m31_512);
    let wg_v608 = eval.m31_add(wg_v605, wg_v607);
    let wg_v609 = eval.felt_get_m31(&wg_v548, 26);
    let wg_v610 = eval.m31_mul(wg_v609, m31_262144);
    let wg_v611 = eval.m31_add(wg_v608, wg_v610);
    let wg_v612 = eval.felt_get_m31(&wg_v548, 27);
    let combination_tmp_8c14f_2 = [
        wg_v555, wg_v562, wg_v569, wg_v576, wg_v583, wg_v590, wg_v597, wg_v604, wg_v611, wg_v612,
    ];
    let combination_limb_0_col82 = combination_tmp_8c14f_2[0];
    eval.set_col(82, combination_limb_0_col82);
    let combination_limb_1_col83 = combination_tmp_8c14f_2[1];
    eval.set_col(83, combination_limb_1_col83);
    let combination_limb_2_col84 = combination_tmp_8c14f_2[2];
    eval.set_col(84, combination_limb_2_col84);
    let combination_limb_3_col85 = combination_tmp_8c14f_2[3];
    eval.set_col(85, combination_limb_3_col85);
    let combination_limb_4_col86 = combination_tmp_8c14f_2[4];
    eval.set_col(86, combination_limb_4_col86);
    let combination_limb_5_col87 = combination_tmp_8c14f_2[5];
    eval.set_col(87, combination_limb_5_col87);
    let combination_limb_6_col88 = combination_tmp_8c14f_2[6];
    eval.set_col(88, combination_limb_6_col88);
    let combination_limb_7_col89 = combination_tmp_8c14f_2[7];
    eval.set_col(89, combination_limb_7_col89);
    let combination_limb_8_col90 = combination_tmp_8c14f_2[8];
    eval.set_col(90, combination_limb_8_col90);
    let combination_limb_9_col91 = combination_tmp_8c14f_2[9];
    eval.set_col(91, combination_limb_9_col91);
    let wg_v613 = eval.m31_mul(m31_4, input_limb_2_col2);
    let wg_v614 = eval.m31_mul(m31_2, input_limb_12_col12);
    let wg_v615 = eval.m31_add(wg_v613, wg_v614);
    let wg_v616 = eval.m31_mul(m31_3, input_limb_22_col22);
    let wg_v617 = eval.m31_add(wg_v615, wg_v616);
    let wg_v618 = eval.m31_add(wg_v617, input_limb_32_col32);
    let wg_v619 = eval.m31_sub(wg_v618, cube_252_output_limb_0_col72);
    let wg_v620 = eval.m31_add(wg_v619, poseidon_round_keys_output_limb_0_col42);
    let wg_v621 = eval.m31_sub(wg_v620, combination_limb_0_col82);
    let wg_v622 = eval.m31_add(wg_v621, m31_268435458);
    let biased_limb_accumulator_u32_tmp_8c14f_3 = eval.u32_from_m31(wg_v622);
    let wg_v623 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_3);
    let wg_v624 = eval.u16_as_m31(wg_v623);
    let p_coef_col92 = eval.m31_sub(wg_v624, m31_2);
    eval.set_col(92, p_coef_col92);
    let wg_v625 = eval.m31_mul(m31_4, input_limb_2_col2);
    let wg_v626 = eval.m31_mul(m31_2, input_limb_12_col12);
    let wg_v627 = eval.m31_add(wg_v625, wg_v626);
    let wg_v628 = eval.m31_mul(m31_3, input_limb_22_col22);
    let wg_v629 = eval.m31_add(wg_v627, wg_v628);
    let wg_v630 = eval.m31_add(wg_v629, input_limb_32_col32);
    let wg_v631 = eval.m31_sub(wg_v630, cube_252_output_limb_0_col72);
    let wg_v632 = eval.m31_add(wg_v631, poseidon_round_keys_output_limb_0_col42);
    let wg_v633 = eval.m31_sub(wg_v632, combination_limb_0_col82);
    let wg_v634 = eval.m31_sub(wg_v633, p_coef_col92);
    let carry_0_tmp_8c14f_4 = eval.m31_mul(wg_v634, m31_16);
    let wg_v635 = eval.m31_mul(m31_4, input_limb_3_col3);
    let wg_v636 = eval.m31_add(carry_0_tmp_8c14f_4, wg_v635);
    let wg_v637 = eval.m31_mul(m31_2, input_limb_13_col13);
    let wg_v638 = eval.m31_add(wg_v636, wg_v637);
    let wg_v639 = eval.m31_mul(m31_3, input_limb_23_col23);
    let wg_v640 = eval.m31_add(wg_v638, wg_v639);
    let wg_v641 = eval.m31_add(wg_v640, input_limb_33_col33);
    let wg_v642 = eval.m31_sub(wg_v641, cube_252_output_limb_1_col73);
    let wg_v643 = eval.m31_add(wg_v642, poseidon_round_keys_output_limb_1_col43);
    let wg_v644 = eval.m31_sub(wg_v643, combination_limb_1_col83);
    let carry_1_tmp_8c14f_5 = eval.m31_mul(wg_v644, m31_16);
    let wg_v645 = eval.m31_mul(m31_4, input_limb_4_col4);
    let wg_v646 = eval.m31_add(carry_1_tmp_8c14f_5, wg_v645);
    let wg_v647 = eval.m31_mul(m31_2, input_limb_14_col14);
    let wg_v648 = eval.m31_add(wg_v646, wg_v647);
    let wg_v649 = eval.m31_mul(m31_3, input_limb_24_col24);
    let wg_v650 = eval.m31_add(wg_v648, wg_v649);
    let wg_v651 = eval.m31_add(wg_v650, input_limb_34_col34);
    let wg_v652 = eval.m31_sub(wg_v651, cube_252_output_limb_2_col74);
    let wg_v653 = eval.m31_add(wg_v652, poseidon_round_keys_output_limb_2_col44);
    let wg_v654 = eval.m31_sub(wg_v653, combination_limb_2_col84);
    let carry_2_tmp_8c14f_6 = eval.m31_mul(wg_v654, m31_16);
    let wg_v655 = eval.m31_mul(m31_4, input_limb_5_col5);
    let wg_v656 = eval.m31_add(carry_2_tmp_8c14f_6, wg_v655);
    let wg_v657 = eval.m31_mul(m31_2, input_limb_15_col15);
    let wg_v658 = eval.m31_add(wg_v656, wg_v657);
    let wg_v659 = eval.m31_mul(m31_3, input_limb_25_col25);
    let wg_v660 = eval.m31_add(wg_v658, wg_v659);
    let wg_v661 = eval.m31_add(wg_v660, input_limb_35_col35);
    let wg_v662 = eval.m31_sub(wg_v661, cube_252_output_limb_3_col75);
    let wg_v663 = eval.m31_add(wg_v662, poseidon_round_keys_output_limb_3_col45);
    let wg_v664 = eval.m31_sub(wg_v663, combination_limb_3_col85);
    let carry_3_tmp_8c14f_7 = eval.m31_mul(wg_v664, m31_16);
    let wg_v665 = eval.m31_mul(m31_4, input_limb_6_col6);
    let wg_v666 = eval.m31_add(carry_3_tmp_8c14f_7, wg_v665);
    let wg_v667 = eval.m31_mul(m31_2, input_limb_16_col16);
    let wg_v668 = eval.m31_add(wg_v666, wg_v667);
    let wg_v669 = eval.m31_mul(m31_3, input_limb_26_col26);
    let wg_v670 = eval.m31_add(wg_v668, wg_v669);
    let wg_v671 = eval.m31_add(wg_v670, input_limb_36_col36);
    let wg_v672 = eval.m31_sub(wg_v671, cube_252_output_limb_4_col76);
    let wg_v673 = eval.m31_add(wg_v672, poseidon_round_keys_output_limb_4_col46);
    let wg_v674 = eval.m31_sub(wg_v673, combination_limb_4_col86);
    let carry_4_tmp_8c14f_8 = eval.m31_mul(wg_v674, m31_16);
    let wg_v675 = eval.m31_mul(m31_4, input_limb_7_col7);
    let wg_v676 = eval.m31_add(carry_4_tmp_8c14f_8, wg_v675);
    let wg_v677 = eval.m31_mul(m31_2, input_limb_17_col17);
    let wg_v678 = eval.m31_add(wg_v676, wg_v677);
    let wg_v679 = eval.m31_mul(m31_3, input_limb_27_col27);
    let wg_v680 = eval.m31_add(wg_v678, wg_v679);
    let wg_v681 = eval.m31_add(wg_v680, input_limb_37_col37);
    let wg_v682 = eval.m31_sub(wg_v681, cube_252_output_limb_5_col77);
    let wg_v683 = eval.m31_add(wg_v682, poseidon_round_keys_output_limb_5_col47);
    let wg_v684 = eval.m31_sub(wg_v683, combination_limb_5_col87);
    let carry_5_tmp_8c14f_9 = eval.m31_mul(wg_v684, m31_16);
    let wg_v685 = eval.m31_mul(m31_4, input_limb_8_col8);
    let wg_v686 = eval.m31_add(carry_5_tmp_8c14f_9, wg_v685);
    let wg_v687 = eval.m31_mul(m31_2, input_limb_18_col18);
    let wg_v688 = eval.m31_add(wg_v686, wg_v687);
    let wg_v689 = eval.m31_mul(m31_3, input_limb_28_col28);
    let wg_v690 = eval.m31_add(wg_v688, wg_v689);
    let wg_v691 = eval.m31_add(wg_v690, input_limb_38_col38);
    let wg_v692 = eval.m31_sub(wg_v691, cube_252_output_limb_6_col78);
    let wg_v693 = eval.m31_add(wg_v692, poseidon_round_keys_output_limb_6_col48);
    let wg_v694 = eval.m31_sub(wg_v693, combination_limb_6_col88);
    let carry_6_tmp_8c14f_10 = eval.m31_mul(wg_v694, m31_16);
    let wg_v695 = eval.m31_mul(m31_4, input_limb_9_col9);
    let wg_v696 = eval.m31_add(carry_6_tmp_8c14f_10, wg_v695);
    let wg_v697 = eval.m31_mul(m31_2, input_limb_19_col19);
    let wg_v698 = eval.m31_add(wg_v696, wg_v697);
    let wg_v699 = eval.m31_mul(m31_3, input_limb_29_col29);
    let wg_v700 = eval.m31_add(wg_v698, wg_v699);
    let wg_v701 = eval.m31_add(wg_v700, input_limb_39_col39);
    let wg_v702 = eval.m31_sub(wg_v701, cube_252_output_limb_7_col79);
    let wg_v703 = eval.m31_add(wg_v702, poseidon_round_keys_output_limb_7_col49);
    let wg_v704 = eval.m31_sub(wg_v703, combination_limb_7_col89);
    let wg_v705 = eval.m31_mul(p_coef_col92, m31_136);
    let wg_v706 = eval.m31_sub(wg_v704, wg_v705);
    let carry_7_tmp_8c14f_11 = eval.m31_mul(wg_v706, m31_16);
    let wg_v707 = eval.m31_mul(m31_4, input_limb_10_col10);
    let wg_v708 = eval.m31_add(carry_7_tmp_8c14f_11, wg_v707);
    let wg_v709 = eval.m31_mul(m31_2, input_limb_20_col20);
    let wg_v710 = eval.m31_add(wg_v708, wg_v709);
    let wg_v711 = eval.m31_mul(m31_3, input_limb_30_col30);
    let wg_v712 = eval.m31_add(wg_v710, wg_v711);
    let wg_v713 = eval.m31_add(wg_v712, input_limb_40_col40);
    let wg_v714 = eval.m31_sub(wg_v713, cube_252_output_limb_8_col80);
    let wg_v715 = eval.m31_add(wg_v714, poseidon_round_keys_output_limb_8_col50);
    let wg_v716 = eval.m31_sub(wg_v715, combination_limb_8_col90);
    let carry_8_tmp_8c14f_12 = eval.m31_mul(wg_v716, m31_16);
    let wg_v717 = eval.m31_add(p_coef_col92, m31_2);
    let wg_v718 = eval.m31_add(carry_0_tmp_8c14f_4, m31_2);
    let wg_v719 = eval.m31_add(carry_1_tmp_8c14f_5, m31_2);
    let wg_v720 = eval.m31_add(carry_2_tmp_8c14f_6, m31_2);
    eval.set_sub_input_word(31, wg_v717);
    eval.set_sub_input_word(32, wg_v718);
    eval.set_sub_input_word(33, wg_v719);
    eval.set_sub_input_word(34, wg_v720);
    eval.set_lookup_word(53, m31_1027333874);
    let wg_v721 = eval.m31_add(p_coef_col92, m31_2);
    eval.set_lookup_word(54, wg_v721);
    let wg_v722 = eval.m31_add(carry_0_tmp_8c14f_4, m31_2);
    eval.set_lookup_word(55, wg_v722);
    let wg_v723 = eval.m31_add(carry_1_tmp_8c14f_5, m31_2);
    eval.set_lookup_word(56, wg_v723);
    let wg_v724 = eval.m31_add(carry_2_tmp_8c14f_6, m31_2);
    eval.set_lookup_word(57, wg_v724);
    let wg_v725 = eval.m31_add(carry_3_tmp_8c14f_7, m31_2);
    let wg_v726 = eval.m31_add(carry_4_tmp_8c14f_8, m31_2);
    let wg_v727 = eval.m31_add(carry_5_tmp_8c14f_9, m31_2);
    let wg_v728 = eval.m31_add(carry_6_tmp_8c14f_10, m31_2);
    eval.set_sub_input_word(35, wg_v725);
    eval.set_sub_input_word(36, wg_v726);
    eval.set_sub_input_word(37, wg_v727);
    eval.set_sub_input_word(38, wg_v728);
    eval.set_lookup_word(58, m31_1027333874);
    let wg_v729 = eval.m31_add(carry_3_tmp_8c14f_7, m31_2);
    eval.set_lookup_word(59, wg_v729);
    let wg_v730 = eval.m31_add(carry_4_tmp_8c14f_8, m31_2);
    eval.set_lookup_word(60, wg_v730);
    let wg_v731 = eval.m31_add(carry_5_tmp_8c14f_9, m31_2);
    eval.set_lookup_word(61, wg_v731);
    let wg_v732 = eval.m31_add(carry_6_tmp_8c14f_10, m31_2);
    eval.set_lookup_word(62, wg_v732);
    let wg_v733 = eval.m31_add(carry_7_tmp_8c14f_11, m31_2);
    let wg_v734 = eval.m31_add(carry_8_tmp_8c14f_12, m31_2);
    eval.set_sub_input_word(55, wg_v733);
    eval.set_sub_input_word(56, wg_v734);
    eval.set_lookup_word(63, m31_1651211826);
    let wg_v735 = eval.m31_add(carry_7_tmp_8c14f_11, m31_2);
    eval.set_lookup_word(64, wg_v735);
    let wg_v736 = eval.m31_add(carry_8_tmp_8c14f_12, m31_2);
    eval.set_lookup_word(65, wg_v736);
    let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13 = combination_tmp_8c14f_2;
    let wg_v737 = linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13;
    let wg_v738 = wg_v737[0];
    let wg_v739 = wg_v737[1];
    let wg_v740 = wg_v737[2];
    let wg_v741 = wg_v737[3];
    let wg_v742 = wg_v737[4];
    let wg_v743 = wg_v737[5];
    let wg_v744 = wg_v737[6];
    let wg_v745 = wg_v737[7];
    let wg_v746 = wg_v737[8];
    let wg_v747 = wg_v737[9];
    eval.set_sub_input_word(61, wg_v738);
    eval.set_sub_input_word(62, wg_v739);
    eval.set_sub_input_word(63, wg_v740);
    eval.set_sub_input_word(64, wg_v741);
    eval.set_sub_input_word(65, wg_v742);
    eval.set_sub_input_word(66, wg_v743);
    eval.set_sub_input_word(67, wg_v744);
    eval.set_sub_input_word(68, wg_v745);
    eval.set_sub_input_word(69, wg_v746);
    eval.set_sub_input_word(70, wg_v747);
    eval.set_lookup_word(66, m31_1090315331);
    eval.set_lookup_word(67, combination_limb_0_col82);
    eval.set_lookup_word(68, combination_limb_1_col83);
    eval.set_lookup_word(69, combination_limb_2_col84);
    eval.set_lookup_word(70, combination_limb_3_col85);
    eval.set_lookup_word(71, combination_limb_4_col86);
    eval.set_lookup_word(72, combination_limb_5_col87);
    eval.set_lookup_word(73, combination_limb_6_col88);
    eval.set_lookup_word(74, combination_limb_7_col89);
    eval.set_lookup_word(75, combination_limb_8_col90);
    eval.set_lookup_word(76, combination_limb_9_col91);
    let wg_v748 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v749 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v750 =
        eval.felt_from_w27_words(linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_13);
    let wg_v751 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v752 = eval.felt_mul(wg_v751.clone(), wg_v750.clone());
    let wg_v753 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v754 = eval.felt_add(wg_v753.clone(), wg_v752.clone());
    let wg_v755 = eval.felt_get_m31(&wg_v754, 0);
    let wg_v756 = eval.felt_get_m31(&wg_v754, 1);
    let wg_v757 = eval.m31_mul(wg_v756, m31_512);
    let wg_v758 = eval.m31_add(wg_v755, wg_v757);
    let wg_v759 = eval.felt_get_m31(&wg_v754, 2);
    let wg_v760 = eval.m31_mul(wg_v759, m31_262144);
    let wg_v761 = eval.m31_add(wg_v758, wg_v760);
    let wg_v762 = eval.felt_get_m31(&wg_v754, 3);
    let wg_v763 = eval.felt_get_m31(&wg_v754, 4);
    let wg_v764 = eval.m31_mul(wg_v763, m31_512);
    let wg_v765 = eval.m31_add(wg_v762, wg_v764);
    let wg_v766 = eval.felt_get_m31(&wg_v754, 5);
    let wg_v767 = eval.m31_mul(wg_v766, m31_262144);
    let wg_v768 = eval.m31_add(wg_v765, wg_v767);
    let wg_v769 = eval.felt_get_m31(&wg_v754, 6);
    let wg_v770 = eval.felt_get_m31(&wg_v754, 7);
    let wg_v771 = eval.m31_mul(wg_v770, m31_512);
    let wg_v772 = eval.m31_add(wg_v769, wg_v771);
    let wg_v773 = eval.felt_get_m31(&wg_v754, 8);
    let wg_v774 = eval.m31_mul(wg_v773, m31_262144);
    let wg_v775 = eval.m31_add(wg_v772, wg_v774);
    let wg_v776 = eval.felt_get_m31(&wg_v754, 9);
    let wg_v777 = eval.felt_get_m31(&wg_v754, 10);
    let wg_v778 = eval.m31_mul(wg_v777, m31_512);
    let wg_v779 = eval.m31_add(wg_v776, wg_v778);
    let wg_v780 = eval.felt_get_m31(&wg_v754, 11);
    let wg_v781 = eval.m31_mul(wg_v780, m31_262144);
    let wg_v782 = eval.m31_add(wg_v779, wg_v781);
    let wg_v783 = eval.felt_get_m31(&wg_v754, 12);
    let wg_v784 = eval.felt_get_m31(&wg_v754, 13);
    let wg_v785 = eval.m31_mul(wg_v784, m31_512);
    let wg_v786 = eval.m31_add(wg_v783, wg_v785);
    let wg_v787 = eval.felt_get_m31(&wg_v754, 14);
    let wg_v788 = eval.m31_mul(wg_v787, m31_262144);
    let wg_v789 = eval.m31_add(wg_v786, wg_v788);
    let wg_v790 = eval.felt_get_m31(&wg_v754, 15);
    let wg_v791 = eval.felt_get_m31(&wg_v754, 16);
    let wg_v792 = eval.m31_mul(wg_v791, m31_512);
    let wg_v793 = eval.m31_add(wg_v790, wg_v792);
    let wg_v794 = eval.felt_get_m31(&wg_v754, 17);
    let wg_v795 = eval.m31_mul(wg_v794, m31_262144);
    let wg_v796 = eval.m31_add(wg_v793, wg_v795);
    let wg_v797 = eval.felt_get_m31(&wg_v754, 18);
    let wg_v798 = eval.felt_get_m31(&wg_v754, 19);
    let wg_v799 = eval.m31_mul(wg_v798, m31_512);
    let wg_v800 = eval.m31_add(wg_v797, wg_v799);
    let wg_v801 = eval.felt_get_m31(&wg_v754, 20);
    let wg_v802 = eval.m31_mul(wg_v801, m31_262144);
    let wg_v803 = eval.m31_add(wg_v800, wg_v802);
    let wg_v804 = eval.felt_get_m31(&wg_v754, 21);
    let wg_v805 = eval.felt_get_m31(&wg_v754, 22);
    let wg_v806 = eval.m31_mul(wg_v805, m31_512);
    let wg_v807 = eval.m31_add(wg_v804, wg_v806);
    let wg_v808 = eval.felt_get_m31(&wg_v754, 23);
    let wg_v809 = eval.m31_mul(wg_v808, m31_262144);
    let wg_v810 = eval.m31_add(wg_v807, wg_v809);
    let wg_v811 = eval.felt_get_m31(&wg_v754, 24);
    let wg_v812 = eval.felt_get_m31(&wg_v754, 25);
    let wg_v813 = eval.m31_mul(wg_v812, m31_512);
    let wg_v814 = eval.m31_add(wg_v811, wg_v813);
    let wg_v815 = eval.felt_get_m31(&wg_v754, 26);
    let wg_v816 = eval.m31_mul(wg_v815, m31_262144);
    let wg_v817 = eval.m31_add(wg_v814, wg_v816);
    let wg_v818 = eval.felt_get_m31(&wg_v754, 27);
    let combination_tmp_8c14f_14 = [
        wg_v761, wg_v768, wg_v775, wg_v782, wg_v789, wg_v796, wg_v803, wg_v810, wg_v817, wg_v818,
    ];
    let combination_limb_0_col93 = combination_tmp_8c14f_14[0];
    eval.set_col(93, combination_limb_0_col93);
    let combination_limb_1_col94 = combination_tmp_8c14f_14[1];
    eval.set_col(94, combination_limb_1_col94);
    let combination_limb_2_col95 = combination_tmp_8c14f_14[2];
    eval.set_col(95, combination_limb_2_col95);
    let combination_limb_3_col96 = combination_tmp_8c14f_14[3];
    eval.set_col(96, combination_limb_3_col96);
    let combination_limb_4_col97 = combination_tmp_8c14f_14[4];
    eval.set_col(97, combination_limb_4_col97);
    let combination_limb_5_col98 = combination_tmp_8c14f_14[5];
    eval.set_col(98, combination_limb_5_col98);
    let combination_limb_6_col99 = combination_tmp_8c14f_14[6];
    eval.set_col(99, combination_limb_6_col99);
    let combination_limb_7_col100 = combination_tmp_8c14f_14[7];
    eval.set_col(100, combination_limb_7_col100);
    let combination_limb_8_col101 = combination_tmp_8c14f_14[8];
    eval.set_col(101, combination_limb_8_col101);
    let combination_limb_9_col102 = combination_tmp_8c14f_14[9];
    eval.set_col(102, combination_limb_9_col102);
    let wg_v819 = eval.m31_mul(m31_2, combination_limb_0_col82);
    let wg_v820 = eval.m31_sub(wg_v819, combination_limb_0_col93);
    let wg_v821 = eval.m31_add(wg_v820, m31_134217729);
    let biased_limb_accumulator_u32_tmp_8c14f_15 = eval.u32_from_m31(wg_v821);
    let wg_v822 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_15);
    let wg_v823 = eval.u16_as_m31(wg_v822);
    let p_coef_col103 = eval.m31_sub(wg_v823, m31_1);
    eval.set_col(103, p_coef_col103);
    let wg_v824 = eval.m31_mul(m31_2, combination_limb_0_col82);
    let wg_v825 = eval.m31_sub(wg_v824, combination_limb_0_col93);
    let wg_v826 = eval.m31_sub(wg_v825, p_coef_col103);
    let carry_0_tmp_8c14f_16 = eval.m31_mul(wg_v826, m31_16);
    let wg_v827 = eval.m31_mul(m31_2, combination_limb_1_col83);
    let wg_v828 = eval.m31_add(carry_0_tmp_8c14f_16, wg_v827);
    let wg_v829 = eval.m31_sub(wg_v828, combination_limb_1_col94);
    let carry_1_tmp_8c14f_17 = eval.m31_mul(wg_v829, m31_16);
    let wg_v830 = eval.m31_mul(m31_2, combination_limb_2_col84);
    let wg_v831 = eval.m31_add(carry_1_tmp_8c14f_17, wg_v830);
    let wg_v832 = eval.m31_sub(wg_v831, combination_limb_2_col95);
    let carry_2_tmp_8c14f_18 = eval.m31_mul(wg_v832, m31_16);
    let wg_v833 = eval.m31_mul(m31_2, combination_limb_3_col85);
    let wg_v834 = eval.m31_add(carry_2_tmp_8c14f_18, wg_v833);
    let wg_v835 = eval.m31_sub(wg_v834, combination_limb_3_col96);
    let carry_3_tmp_8c14f_19 = eval.m31_mul(wg_v835, m31_16);
    let wg_v836 = eval.m31_mul(m31_2, combination_limb_4_col86);
    let wg_v837 = eval.m31_add(carry_3_tmp_8c14f_19, wg_v836);
    let wg_v838 = eval.m31_sub(wg_v837, combination_limb_4_col97);
    let carry_4_tmp_8c14f_20 = eval.m31_mul(wg_v838, m31_16);
    let wg_v839 = eval.m31_mul(m31_2, combination_limb_5_col87);
    let wg_v840 = eval.m31_add(carry_4_tmp_8c14f_20, wg_v839);
    let wg_v841 = eval.m31_sub(wg_v840, combination_limb_5_col98);
    let carry_5_tmp_8c14f_21 = eval.m31_mul(wg_v841, m31_16);
    let wg_v842 = eval.m31_mul(m31_2, combination_limb_6_col88);
    let wg_v843 = eval.m31_add(carry_5_tmp_8c14f_21, wg_v842);
    let wg_v844 = eval.m31_sub(wg_v843, combination_limb_6_col99);
    let carry_6_tmp_8c14f_22 = eval.m31_mul(wg_v844, m31_16);
    let wg_v845 = eval.m31_mul(m31_2, combination_limb_7_col89);
    let wg_v846 = eval.m31_add(carry_6_tmp_8c14f_22, wg_v845);
    let wg_v847 = eval.m31_sub(wg_v846, combination_limb_7_col100);
    let wg_v848 = eval.m31_mul(p_coef_col103, m31_136);
    let wg_v849 = eval.m31_sub(wg_v847, wg_v848);
    let carry_7_tmp_8c14f_23 = eval.m31_mul(wg_v849, m31_16);
    let wg_v850 = eval.m31_mul(m31_2, combination_limb_8_col90);
    let wg_v851 = eval.m31_add(carry_7_tmp_8c14f_23, wg_v850);
    let wg_v852 = eval.m31_sub(wg_v851, combination_limb_8_col101);
    let carry_8_tmp_8c14f_24 = eval.m31_mul(wg_v852, m31_16);
    let linear_combination_n_1_coefs_2_output_tmp_8c14f_34 = combination_tmp_8c14f_14;
    let poseidon_partial_round_output_tmp_8c14f_35 = [
        cube_252_output_tmp_8c14f_1,
        linear_combination_n_1_coefs_2_output_tmp_8c14f_34,
    ];
    let wg_v853 = poseidon_partial_round_output_tmp_8c14f_35[1];
    let wg_v854 = wg_v853[0];
    let wg_v855 = wg_v853[1];
    let wg_v856 = wg_v853[2];
    let wg_v857 = wg_v853[3];
    let wg_v858 = wg_v853[4];
    let wg_v859 = wg_v853[5];
    let wg_v860 = wg_v853[6];
    let wg_v861 = wg_v853[7];
    let wg_v862 = wg_v853[8];
    let wg_v863 = wg_v853[9];
    eval.set_sub_input_word(11, wg_v854);
    eval.set_sub_input_word(12, wg_v855);
    eval.set_sub_input_word(13, wg_v856);
    eval.set_sub_input_word(14, wg_v857);
    eval.set_sub_input_word(15, wg_v858);
    eval.set_sub_input_word(16, wg_v859);
    eval.set_sub_input_word(17, wg_v860);
    eval.set_sub_input_word(18, wg_v861);
    eval.set_sub_input_word(19, wg_v862);
    eval.set_sub_input_word(20, wg_v863);
    let cube_252_output_tmp_8c14f_36 =
        eval.deduce_cube_252(poseidon_partial_round_output_tmp_8c14f_35[1]);
    let cube_252_output_limb_0_col104 = cube_252_output_tmp_8c14f_36[0];
    eval.set_col(104, cube_252_output_limb_0_col104);
    let cube_252_output_limb_1_col105 = cube_252_output_tmp_8c14f_36[1];
    eval.set_col(105, cube_252_output_limb_1_col105);
    let cube_252_output_limb_2_col106 = cube_252_output_tmp_8c14f_36[2];
    eval.set_col(106, cube_252_output_limb_2_col106);
    let cube_252_output_limb_3_col107 = cube_252_output_tmp_8c14f_36[3];
    eval.set_col(107, cube_252_output_limb_3_col107);
    let cube_252_output_limb_4_col108 = cube_252_output_tmp_8c14f_36[4];
    eval.set_col(108, cube_252_output_limb_4_col108);
    let cube_252_output_limb_5_col109 = cube_252_output_tmp_8c14f_36[5];
    eval.set_col(109, cube_252_output_limb_5_col109);
    let cube_252_output_limb_6_col110 = cube_252_output_tmp_8c14f_36[6];
    eval.set_col(110, cube_252_output_limb_6_col110);
    let cube_252_output_limb_7_col111 = cube_252_output_tmp_8c14f_36[7];
    eval.set_col(111, cube_252_output_limb_7_col111);
    let cube_252_output_limb_8_col112 = cube_252_output_tmp_8c14f_36[8];
    eval.set_col(112, cube_252_output_limb_8_col112);
    let cube_252_output_limb_9_col113 = cube_252_output_tmp_8c14f_36[9];
    eval.set_col(113, cube_252_output_limb_9_col113);
    eval.set_lookup_word(77, m31_1987997202);
    eval.set_lookup_word(78, combination_limb_0_col93);
    eval.set_lookup_word(79, combination_limb_1_col94);
    eval.set_lookup_word(80, combination_limb_2_col95);
    eval.set_lookup_word(81, combination_limb_3_col96);
    eval.set_lookup_word(82, combination_limb_4_col97);
    eval.set_lookup_word(83, combination_limb_5_col98);
    eval.set_lookup_word(84, combination_limb_6_col99);
    eval.set_lookup_word(85, combination_limb_7_col100);
    eval.set_lookup_word(86, combination_limb_8_col101);
    eval.set_lookup_word(87, combination_limb_9_col102);
    eval.set_lookup_word(88, cube_252_output_limb_0_col104);
    eval.set_lookup_word(89, cube_252_output_limb_1_col105);
    eval.set_lookup_word(90, cube_252_output_limb_2_col106);
    eval.set_lookup_word(91, cube_252_output_limb_3_col107);
    eval.set_lookup_word(92, cube_252_output_limb_4_col108);
    eval.set_lookup_word(93, cube_252_output_limb_5_col109);
    eval.set_lookup_word(94, cube_252_output_limb_6_col110);
    eval.set_lookup_word(95, cube_252_output_limb_7_col111);
    eval.set_lookup_word(96, cube_252_output_limb_8_col112);
    eval.set_lookup_word(97, cube_252_output_limb_9_col113);
    let wg_v864 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v865 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v866 = eval.input(22);
    let wg_v867 = eval.input(23);
    let wg_v868 = eval.input(24);
    let wg_v869 = eval.input(25);
    let wg_v870 = eval.input(26);
    let wg_v871 = eval.input(27);
    let wg_v872 = eval.input(28);
    let wg_v873 = eval.input(29);
    let wg_v874 = eval.input(30);
    let wg_v875 = eval.input(31);
    let wg_v876 = [
        wg_v866, wg_v867, wg_v868, wg_v869, wg_v870, wg_v871, wg_v872, wg_v873, wg_v874, wg_v875,
    ];
    let wg_v877 = eval.felt_from_w27_words(wg_v876);
    let wg_v878 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v879 = eval.felt_mul(wg_v878.clone(), wg_v877.clone());
    let wg_v880 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v881 = eval.felt_add(wg_v880.clone(), wg_v879.clone());
    let wg_v882 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v883 = eval.input(32);
    let wg_v884 = eval.input(33);
    let wg_v885 = eval.input(34);
    let wg_v886 = eval.input(35);
    let wg_v887 = eval.input(36);
    let wg_v888 = eval.input(37);
    let wg_v889 = eval.input(38);
    let wg_v890 = eval.input(39);
    let wg_v891 = eval.input(40);
    let wg_v892 = eval.input(41);
    let wg_v893 = [
        wg_v883, wg_v884, wg_v885, wg_v886, wg_v887, wg_v888, wg_v889, wg_v890, wg_v891, wg_v892,
    ];
    let wg_v894 = eval.felt_from_w27_words(wg_v893);
    let wg_v895 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v896 = eval.felt_mul(wg_v895.clone(), wg_v894.clone());
    let wg_v897 = eval.felt_add(wg_v881.clone(), wg_v896.clone());
    let wg_v898 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v899 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_35[0]);
    let wg_v900 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v901 = eval.felt_mul(wg_v900.clone(), wg_v899.clone());
    let wg_v902 = eval.felt_add(wg_v897.clone(), wg_v901.clone());
    let wg_v903 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v904 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_35[1]);
    let wg_v905 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v906 = eval.felt_mul(wg_v905.clone(), wg_v904.clone());
    let wg_v907 = eval.felt_add(wg_v902.clone(), wg_v906.clone());
    let wg_v908 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v909 = eval.felt_from_w27_words(cube_252_output_tmp_8c14f_36);
    let wg_v910 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v911 = eval.felt_mul(wg_v910.clone(), wg_v909.clone());
    let wg_v912 = eval.felt_sub(wg_v907.clone(), wg_v911.clone());
    let wg_v913 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v914 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_8c14f_0[1]);
    let wg_v915 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v916 = eval.felt_mul(wg_v915.clone(), wg_v914.clone());
    let wg_v917 = eval.felt_add(wg_v912.clone(), wg_v916.clone());
    let wg_v918 = eval.felt_get_m31(&wg_v917, 0);
    let wg_v919 = eval.felt_get_m31(&wg_v917, 1);
    let wg_v920 = eval.m31_mul(wg_v919, m31_512);
    let wg_v921 = eval.m31_add(wg_v918, wg_v920);
    let wg_v922 = eval.felt_get_m31(&wg_v917, 2);
    let wg_v923 = eval.m31_mul(wg_v922, m31_262144);
    let wg_v924 = eval.m31_add(wg_v921, wg_v923);
    let wg_v925 = eval.felt_get_m31(&wg_v917, 3);
    let wg_v926 = eval.felt_get_m31(&wg_v917, 4);
    let wg_v927 = eval.m31_mul(wg_v926, m31_512);
    let wg_v928 = eval.m31_add(wg_v925, wg_v927);
    let wg_v929 = eval.felt_get_m31(&wg_v917, 5);
    let wg_v930 = eval.m31_mul(wg_v929, m31_262144);
    let wg_v931 = eval.m31_add(wg_v928, wg_v930);
    let wg_v932 = eval.felt_get_m31(&wg_v917, 6);
    let wg_v933 = eval.felt_get_m31(&wg_v917, 7);
    let wg_v934 = eval.m31_mul(wg_v933, m31_512);
    let wg_v935 = eval.m31_add(wg_v932, wg_v934);
    let wg_v936 = eval.felt_get_m31(&wg_v917, 8);
    let wg_v937 = eval.m31_mul(wg_v936, m31_262144);
    let wg_v938 = eval.m31_add(wg_v935, wg_v937);
    let wg_v939 = eval.felt_get_m31(&wg_v917, 9);
    let wg_v940 = eval.felt_get_m31(&wg_v917, 10);
    let wg_v941 = eval.m31_mul(wg_v940, m31_512);
    let wg_v942 = eval.m31_add(wg_v939, wg_v941);
    let wg_v943 = eval.felt_get_m31(&wg_v917, 11);
    let wg_v944 = eval.m31_mul(wg_v943, m31_262144);
    let wg_v945 = eval.m31_add(wg_v942, wg_v944);
    let wg_v946 = eval.felt_get_m31(&wg_v917, 12);
    let wg_v947 = eval.felt_get_m31(&wg_v917, 13);
    let wg_v948 = eval.m31_mul(wg_v947, m31_512);
    let wg_v949 = eval.m31_add(wg_v946, wg_v948);
    let wg_v950 = eval.felt_get_m31(&wg_v917, 14);
    let wg_v951 = eval.m31_mul(wg_v950, m31_262144);
    let wg_v952 = eval.m31_add(wg_v949, wg_v951);
    let wg_v953 = eval.felt_get_m31(&wg_v917, 15);
    let wg_v954 = eval.felt_get_m31(&wg_v917, 16);
    let wg_v955 = eval.m31_mul(wg_v954, m31_512);
    let wg_v956 = eval.m31_add(wg_v953, wg_v955);
    let wg_v957 = eval.felt_get_m31(&wg_v917, 17);
    let wg_v958 = eval.m31_mul(wg_v957, m31_262144);
    let wg_v959 = eval.m31_add(wg_v956, wg_v958);
    let wg_v960 = eval.felt_get_m31(&wg_v917, 18);
    let wg_v961 = eval.felt_get_m31(&wg_v917, 19);
    let wg_v962 = eval.m31_mul(wg_v961, m31_512);
    let wg_v963 = eval.m31_add(wg_v960, wg_v962);
    let wg_v964 = eval.felt_get_m31(&wg_v917, 20);
    let wg_v965 = eval.m31_mul(wg_v964, m31_262144);
    let wg_v966 = eval.m31_add(wg_v963, wg_v965);
    let wg_v967 = eval.felt_get_m31(&wg_v917, 21);
    let wg_v968 = eval.felt_get_m31(&wg_v917, 22);
    let wg_v969 = eval.m31_mul(wg_v968, m31_512);
    let wg_v970 = eval.m31_add(wg_v967, wg_v969);
    let wg_v971 = eval.felt_get_m31(&wg_v917, 23);
    let wg_v972 = eval.m31_mul(wg_v971, m31_262144);
    let wg_v973 = eval.m31_add(wg_v970, wg_v972);
    let wg_v974 = eval.felt_get_m31(&wg_v917, 24);
    let wg_v975 = eval.felt_get_m31(&wg_v917, 25);
    let wg_v976 = eval.m31_mul(wg_v975, m31_512);
    let wg_v977 = eval.m31_add(wg_v974, wg_v976);
    let wg_v978 = eval.felt_get_m31(&wg_v917, 26);
    let wg_v979 = eval.m31_mul(wg_v978, m31_262144);
    let wg_v980 = eval.m31_add(wg_v977, wg_v979);
    let wg_v981 = eval.felt_get_m31(&wg_v917, 27);
    let combination_tmp_8c14f_37 = [
        wg_v924, wg_v931, wg_v938, wg_v945, wg_v952, wg_v959, wg_v966, wg_v973, wg_v980, wg_v981,
    ];
    let combination_limb_0_col114 = combination_tmp_8c14f_37[0];
    eval.set_col(114, combination_limb_0_col114);
    let combination_limb_1_col115 = combination_tmp_8c14f_37[1];
    eval.set_col(115, combination_limb_1_col115);
    let combination_limb_2_col116 = combination_tmp_8c14f_37[2];
    eval.set_col(116, combination_limb_2_col116);
    let combination_limb_3_col117 = combination_tmp_8c14f_37[3];
    eval.set_col(117, combination_limb_3_col117);
    let combination_limb_4_col118 = combination_tmp_8c14f_37[4];
    eval.set_col(118, combination_limb_4_col118);
    let combination_limb_5_col119 = combination_tmp_8c14f_37[5];
    eval.set_col(119, combination_limb_5_col119);
    let combination_limb_6_col120 = combination_tmp_8c14f_37[6];
    eval.set_col(120, combination_limb_6_col120);
    let combination_limb_7_col121 = combination_tmp_8c14f_37[7];
    eval.set_col(121, combination_limb_7_col121);
    let combination_limb_8_col122 = combination_tmp_8c14f_37[8];
    eval.set_col(122, combination_limb_8_col122);
    let combination_limb_9_col123 = combination_tmp_8c14f_37[9];
    eval.set_col(123, combination_limb_9_col123);
    let wg_v982 = eval.m31_mul(m31_4, input_limb_22_col22);
    let wg_v983 = eval.m31_mul(m31_2, input_limb_32_col32);
    let wg_v984 = eval.m31_add(wg_v982, wg_v983);
    let wg_v985 = eval.m31_mul(m31_3, cube_252_output_limb_0_col72);
    let wg_v986 = eval.m31_add(wg_v984, wg_v985);
    let wg_v987 = eval.m31_add(wg_v986, combination_limb_0_col93);
    let wg_v988 = eval.m31_sub(wg_v987, cube_252_output_limb_0_col104);
    let wg_v989 = eval.m31_add(wg_v988, poseidon_round_keys_output_limb_10_col52);
    let wg_v990 = eval.m31_sub(wg_v989, combination_limb_0_col114);
    let wg_v991 = eval.m31_add(wg_v990, m31_268435458);
    let biased_limb_accumulator_u32_tmp_8c14f_38 = eval.u32_from_m31(wg_v991);
    let wg_v992 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_38);
    let wg_v993 = eval.u16_as_m31(wg_v992);
    let p_coef_col124 = eval.m31_sub(wg_v993, m31_2);
    eval.set_col(124, p_coef_col124);
    let wg_v994 = eval.m31_mul(m31_4, input_limb_22_col22);
    let wg_v995 = eval.m31_mul(m31_2, input_limb_32_col32);
    let wg_v996 = eval.m31_add(wg_v994, wg_v995);
    let wg_v997 = eval.m31_mul(m31_3, cube_252_output_limb_0_col72);
    let wg_v998 = eval.m31_add(wg_v996, wg_v997);
    let wg_v999 = eval.m31_add(wg_v998, combination_limb_0_col93);
    let wg_v1000 = eval.m31_sub(wg_v999, cube_252_output_limb_0_col104);
    let wg_v1001 = eval.m31_add(wg_v1000, poseidon_round_keys_output_limb_10_col52);
    let wg_v1002 = eval.m31_sub(wg_v1001, combination_limb_0_col114);
    let wg_v1003 = eval.m31_sub(wg_v1002, p_coef_col124);
    let carry_0_tmp_8c14f_39 = eval.m31_mul(wg_v1003, m31_16);
    let wg_v1004 = eval.m31_mul(m31_4, input_limb_23_col23);
    let wg_v1005 = eval.m31_add(carry_0_tmp_8c14f_39, wg_v1004);
    let wg_v1006 = eval.m31_mul(m31_2, input_limb_33_col33);
    let wg_v1007 = eval.m31_add(wg_v1005, wg_v1006);
    let wg_v1008 = eval.m31_mul(m31_3, cube_252_output_limb_1_col73);
    let wg_v1009 = eval.m31_add(wg_v1007, wg_v1008);
    let wg_v1010 = eval.m31_add(wg_v1009, combination_limb_1_col94);
    let wg_v1011 = eval.m31_sub(wg_v1010, cube_252_output_limb_1_col105);
    let wg_v1012 = eval.m31_add(wg_v1011, poseidon_round_keys_output_limb_11_col53);
    let wg_v1013 = eval.m31_sub(wg_v1012, combination_limb_1_col115);
    let carry_1_tmp_8c14f_40 = eval.m31_mul(wg_v1013, m31_16);
    let wg_v1014 = eval.m31_mul(m31_4, input_limb_24_col24);
    let wg_v1015 = eval.m31_add(carry_1_tmp_8c14f_40, wg_v1014);
    let wg_v1016 = eval.m31_mul(m31_2, input_limb_34_col34);
    let wg_v1017 = eval.m31_add(wg_v1015, wg_v1016);
    let wg_v1018 = eval.m31_mul(m31_3, cube_252_output_limb_2_col74);
    let wg_v1019 = eval.m31_add(wg_v1017, wg_v1018);
    let wg_v1020 = eval.m31_add(wg_v1019, combination_limb_2_col95);
    let wg_v1021 = eval.m31_sub(wg_v1020, cube_252_output_limb_2_col106);
    let wg_v1022 = eval.m31_add(wg_v1021, poseidon_round_keys_output_limb_12_col54);
    let wg_v1023 = eval.m31_sub(wg_v1022, combination_limb_2_col116);
    let carry_2_tmp_8c14f_41 = eval.m31_mul(wg_v1023, m31_16);
    let wg_v1024 = eval.m31_mul(m31_4, input_limb_25_col25);
    let wg_v1025 = eval.m31_add(carry_2_tmp_8c14f_41, wg_v1024);
    let wg_v1026 = eval.m31_mul(m31_2, input_limb_35_col35);
    let wg_v1027 = eval.m31_add(wg_v1025, wg_v1026);
    let wg_v1028 = eval.m31_mul(m31_3, cube_252_output_limb_3_col75);
    let wg_v1029 = eval.m31_add(wg_v1027, wg_v1028);
    let wg_v1030 = eval.m31_add(wg_v1029, combination_limb_3_col96);
    let wg_v1031 = eval.m31_sub(wg_v1030, cube_252_output_limb_3_col107);
    let wg_v1032 = eval.m31_add(wg_v1031, poseidon_round_keys_output_limb_13_col55);
    let wg_v1033 = eval.m31_sub(wg_v1032, combination_limb_3_col117);
    let carry_3_tmp_8c14f_42 = eval.m31_mul(wg_v1033, m31_16);
    let wg_v1034 = eval.m31_mul(m31_4, input_limb_26_col26);
    let wg_v1035 = eval.m31_add(carry_3_tmp_8c14f_42, wg_v1034);
    let wg_v1036 = eval.m31_mul(m31_2, input_limb_36_col36);
    let wg_v1037 = eval.m31_add(wg_v1035, wg_v1036);
    let wg_v1038 = eval.m31_mul(m31_3, cube_252_output_limb_4_col76);
    let wg_v1039 = eval.m31_add(wg_v1037, wg_v1038);
    let wg_v1040 = eval.m31_add(wg_v1039, combination_limb_4_col97);
    let wg_v1041 = eval.m31_sub(wg_v1040, cube_252_output_limb_4_col108);
    let wg_v1042 = eval.m31_add(wg_v1041, poseidon_round_keys_output_limb_14_col56);
    let wg_v1043 = eval.m31_sub(wg_v1042, combination_limb_4_col118);
    let carry_4_tmp_8c14f_43 = eval.m31_mul(wg_v1043, m31_16);
    let wg_v1044 = eval.m31_mul(m31_4, input_limb_27_col27);
    let wg_v1045 = eval.m31_add(carry_4_tmp_8c14f_43, wg_v1044);
    let wg_v1046 = eval.m31_mul(m31_2, input_limb_37_col37);
    let wg_v1047 = eval.m31_add(wg_v1045, wg_v1046);
    let wg_v1048 = eval.m31_mul(m31_3, cube_252_output_limb_5_col77);
    let wg_v1049 = eval.m31_add(wg_v1047, wg_v1048);
    let wg_v1050 = eval.m31_add(wg_v1049, combination_limb_5_col98);
    let wg_v1051 = eval.m31_sub(wg_v1050, cube_252_output_limb_5_col109);
    let wg_v1052 = eval.m31_add(wg_v1051, poseidon_round_keys_output_limb_15_col57);
    let wg_v1053 = eval.m31_sub(wg_v1052, combination_limb_5_col119);
    let carry_5_tmp_8c14f_44 = eval.m31_mul(wg_v1053, m31_16);
    let wg_v1054 = eval.m31_mul(m31_4, input_limb_28_col28);
    let wg_v1055 = eval.m31_add(carry_5_tmp_8c14f_44, wg_v1054);
    let wg_v1056 = eval.m31_mul(m31_2, input_limb_38_col38);
    let wg_v1057 = eval.m31_add(wg_v1055, wg_v1056);
    let wg_v1058 = eval.m31_mul(m31_3, cube_252_output_limb_6_col78);
    let wg_v1059 = eval.m31_add(wg_v1057, wg_v1058);
    let wg_v1060 = eval.m31_add(wg_v1059, combination_limb_6_col99);
    let wg_v1061 = eval.m31_sub(wg_v1060, cube_252_output_limb_6_col110);
    let wg_v1062 = eval.m31_add(wg_v1061, poseidon_round_keys_output_limb_16_col58);
    let wg_v1063 = eval.m31_sub(wg_v1062, combination_limb_6_col120);
    let carry_6_tmp_8c14f_45 = eval.m31_mul(wg_v1063, m31_16);
    let wg_v1064 = eval.m31_mul(m31_4, input_limb_29_col29);
    let wg_v1065 = eval.m31_add(carry_6_tmp_8c14f_45, wg_v1064);
    let wg_v1066 = eval.m31_mul(m31_2, input_limb_39_col39);
    let wg_v1067 = eval.m31_add(wg_v1065, wg_v1066);
    let wg_v1068 = eval.m31_mul(m31_3, cube_252_output_limb_7_col79);
    let wg_v1069 = eval.m31_add(wg_v1067, wg_v1068);
    let wg_v1070 = eval.m31_add(wg_v1069, combination_limb_7_col100);
    let wg_v1071 = eval.m31_sub(wg_v1070, cube_252_output_limb_7_col111);
    let wg_v1072 = eval.m31_add(wg_v1071, poseidon_round_keys_output_limb_17_col59);
    let wg_v1073 = eval.m31_sub(wg_v1072, combination_limb_7_col121);
    let wg_v1074 = eval.m31_mul(p_coef_col124, m31_136);
    let wg_v1075 = eval.m31_sub(wg_v1073, wg_v1074);
    let carry_7_tmp_8c14f_46 = eval.m31_mul(wg_v1075, m31_16);
    let wg_v1076 = eval.m31_mul(m31_4, input_limb_30_col30);
    let wg_v1077 = eval.m31_add(carry_7_tmp_8c14f_46, wg_v1076);
    let wg_v1078 = eval.m31_mul(m31_2, input_limb_40_col40);
    let wg_v1079 = eval.m31_add(wg_v1077, wg_v1078);
    let wg_v1080 = eval.m31_mul(m31_3, cube_252_output_limb_8_col80);
    let wg_v1081 = eval.m31_add(wg_v1079, wg_v1080);
    let wg_v1082 = eval.m31_add(wg_v1081, combination_limb_8_col101);
    let wg_v1083 = eval.m31_sub(wg_v1082, cube_252_output_limb_8_col112);
    let wg_v1084 = eval.m31_add(wg_v1083, poseidon_round_keys_output_limb_18_col60);
    let wg_v1085 = eval.m31_sub(wg_v1084, combination_limb_8_col122);
    let carry_8_tmp_8c14f_47 = eval.m31_mul(wg_v1085, m31_16);
    let wg_v1086 = eval.m31_add(p_coef_col124, m31_2);
    let wg_v1087 = eval.m31_add(carry_0_tmp_8c14f_39, m31_2);
    let wg_v1088 = eval.m31_add(carry_1_tmp_8c14f_40, m31_2);
    let wg_v1089 = eval.m31_add(carry_2_tmp_8c14f_41, m31_2);
    eval.set_sub_input_word(39, wg_v1086);
    eval.set_sub_input_word(40, wg_v1087);
    eval.set_sub_input_word(41, wg_v1088);
    eval.set_sub_input_word(42, wg_v1089);
    eval.set_lookup_word(98, m31_1027333874);
    let wg_v1090 = eval.m31_add(p_coef_col124, m31_2);
    eval.set_lookup_word(99, wg_v1090);
    let wg_v1091 = eval.m31_add(carry_0_tmp_8c14f_39, m31_2);
    eval.set_lookup_word(100, wg_v1091);
    let wg_v1092 = eval.m31_add(carry_1_tmp_8c14f_40, m31_2);
    eval.set_lookup_word(101, wg_v1092);
    let wg_v1093 = eval.m31_add(carry_2_tmp_8c14f_41, m31_2);
    eval.set_lookup_word(102, wg_v1093);
    let wg_v1094 = eval.m31_add(carry_3_tmp_8c14f_42, m31_2);
    let wg_v1095 = eval.m31_add(carry_4_tmp_8c14f_43, m31_2);
    let wg_v1096 = eval.m31_add(carry_5_tmp_8c14f_44, m31_2);
    let wg_v1097 = eval.m31_add(carry_6_tmp_8c14f_45, m31_2);
    eval.set_sub_input_word(43, wg_v1094);
    eval.set_sub_input_word(44, wg_v1095);
    eval.set_sub_input_word(45, wg_v1096);
    eval.set_sub_input_word(46, wg_v1097);
    eval.set_lookup_word(103, m31_1027333874);
    let wg_v1098 = eval.m31_add(carry_3_tmp_8c14f_42, m31_2);
    eval.set_lookup_word(104, wg_v1098);
    let wg_v1099 = eval.m31_add(carry_4_tmp_8c14f_43, m31_2);
    eval.set_lookup_word(105, wg_v1099);
    let wg_v1100 = eval.m31_add(carry_5_tmp_8c14f_44, m31_2);
    eval.set_lookup_word(106, wg_v1100);
    let wg_v1101 = eval.m31_add(carry_6_tmp_8c14f_45, m31_2);
    eval.set_lookup_word(107, wg_v1101);
    let wg_v1102 = eval.m31_add(carry_7_tmp_8c14f_46, m31_2);
    let wg_v1103 = eval.m31_add(carry_8_tmp_8c14f_47, m31_2);
    eval.set_sub_input_word(57, wg_v1102);
    eval.set_sub_input_word(58, wg_v1103);
    eval.set_lookup_word(108, m31_1651211826);
    let wg_v1104 = eval.m31_add(carry_7_tmp_8c14f_46, m31_2);
    eval.set_lookup_word(109, wg_v1104);
    let wg_v1105 = eval.m31_add(carry_8_tmp_8c14f_47, m31_2);
    eval.set_lookup_word(110, wg_v1105);
    let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48 = combination_tmp_8c14f_37;
    let wg_v1106 = linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48;
    let wg_v1107 = wg_v1106[0];
    let wg_v1108 = wg_v1106[1];
    let wg_v1109 = wg_v1106[2];
    let wg_v1110 = wg_v1106[3];
    let wg_v1111 = wg_v1106[4];
    let wg_v1112 = wg_v1106[5];
    let wg_v1113 = wg_v1106[6];
    let wg_v1114 = wg_v1106[7];
    let wg_v1115 = wg_v1106[8];
    let wg_v1116 = wg_v1106[9];
    eval.set_sub_input_word(71, wg_v1107);
    eval.set_sub_input_word(72, wg_v1108);
    eval.set_sub_input_word(73, wg_v1109);
    eval.set_sub_input_word(74, wg_v1110);
    eval.set_sub_input_word(75, wg_v1111);
    eval.set_sub_input_word(76, wg_v1112);
    eval.set_sub_input_word(77, wg_v1113);
    eval.set_sub_input_word(78, wg_v1114);
    eval.set_sub_input_word(79, wg_v1115);
    eval.set_sub_input_word(80, wg_v1116);
    eval.set_lookup_word(111, m31_1090315331);
    eval.set_lookup_word(112, combination_limb_0_col114);
    eval.set_lookup_word(113, combination_limb_1_col115);
    eval.set_lookup_word(114, combination_limb_2_col116);
    eval.set_lookup_word(115, combination_limb_3_col117);
    eval.set_lookup_word(116, combination_limb_4_col118);
    eval.set_lookup_word(117, combination_limb_5_col119);
    eval.set_lookup_word(118, combination_limb_6_col120);
    eval.set_lookup_word(119, combination_limb_7_col121);
    eval.set_lookup_word(120, combination_limb_8_col122);
    eval.set_lookup_word(121, combination_limb_9_col123);
    let wg_v1117 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1118 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1119 =
        eval.felt_from_w27_words(linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_48);
    let wg_v1120 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1121 = eval.felt_mul(wg_v1120.clone(), wg_v1119.clone());
    let wg_v1122 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1123 = eval.felt_add(wg_v1122.clone(), wg_v1121.clone());
    let wg_v1124 = eval.felt_get_m31(&wg_v1123, 0);
    let wg_v1125 = eval.felt_get_m31(&wg_v1123, 1);
    let wg_v1126 = eval.m31_mul(wg_v1125, m31_512);
    let wg_v1127 = eval.m31_add(wg_v1124, wg_v1126);
    let wg_v1128 = eval.felt_get_m31(&wg_v1123, 2);
    let wg_v1129 = eval.m31_mul(wg_v1128, m31_262144);
    let wg_v1130 = eval.m31_add(wg_v1127, wg_v1129);
    let wg_v1131 = eval.felt_get_m31(&wg_v1123, 3);
    let wg_v1132 = eval.felt_get_m31(&wg_v1123, 4);
    let wg_v1133 = eval.m31_mul(wg_v1132, m31_512);
    let wg_v1134 = eval.m31_add(wg_v1131, wg_v1133);
    let wg_v1135 = eval.felt_get_m31(&wg_v1123, 5);
    let wg_v1136 = eval.m31_mul(wg_v1135, m31_262144);
    let wg_v1137 = eval.m31_add(wg_v1134, wg_v1136);
    let wg_v1138 = eval.felt_get_m31(&wg_v1123, 6);
    let wg_v1139 = eval.felt_get_m31(&wg_v1123, 7);
    let wg_v1140 = eval.m31_mul(wg_v1139, m31_512);
    let wg_v1141 = eval.m31_add(wg_v1138, wg_v1140);
    let wg_v1142 = eval.felt_get_m31(&wg_v1123, 8);
    let wg_v1143 = eval.m31_mul(wg_v1142, m31_262144);
    let wg_v1144 = eval.m31_add(wg_v1141, wg_v1143);
    let wg_v1145 = eval.felt_get_m31(&wg_v1123, 9);
    let wg_v1146 = eval.felt_get_m31(&wg_v1123, 10);
    let wg_v1147 = eval.m31_mul(wg_v1146, m31_512);
    let wg_v1148 = eval.m31_add(wg_v1145, wg_v1147);
    let wg_v1149 = eval.felt_get_m31(&wg_v1123, 11);
    let wg_v1150 = eval.m31_mul(wg_v1149, m31_262144);
    let wg_v1151 = eval.m31_add(wg_v1148, wg_v1150);
    let wg_v1152 = eval.felt_get_m31(&wg_v1123, 12);
    let wg_v1153 = eval.felt_get_m31(&wg_v1123, 13);
    let wg_v1154 = eval.m31_mul(wg_v1153, m31_512);
    let wg_v1155 = eval.m31_add(wg_v1152, wg_v1154);
    let wg_v1156 = eval.felt_get_m31(&wg_v1123, 14);
    let wg_v1157 = eval.m31_mul(wg_v1156, m31_262144);
    let wg_v1158 = eval.m31_add(wg_v1155, wg_v1157);
    let wg_v1159 = eval.felt_get_m31(&wg_v1123, 15);
    let wg_v1160 = eval.felt_get_m31(&wg_v1123, 16);
    let wg_v1161 = eval.m31_mul(wg_v1160, m31_512);
    let wg_v1162 = eval.m31_add(wg_v1159, wg_v1161);
    let wg_v1163 = eval.felt_get_m31(&wg_v1123, 17);
    let wg_v1164 = eval.m31_mul(wg_v1163, m31_262144);
    let wg_v1165 = eval.m31_add(wg_v1162, wg_v1164);
    let wg_v1166 = eval.felt_get_m31(&wg_v1123, 18);
    let wg_v1167 = eval.felt_get_m31(&wg_v1123, 19);
    let wg_v1168 = eval.m31_mul(wg_v1167, m31_512);
    let wg_v1169 = eval.m31_add(wg_v1166, wg_v1168);
    let wg_v1170 = eval.felt_get_m31(&wg_v1123, 20);
    let wg_v1171 = eval.m31_mul(wg_v1170, m31_262144);
    let wg_v1172 = eval.m31_add(wg_v1169, wg_v1171);
    let wg_v1173 = eval.felt_get_m31(&wg_v1123, 21);
    let wg_v1174 = eval.felt_get_m31(&wg_v1123, 22);
    let wg_v1175 = eval.m31_mul(wg_v1174, m31_512);
    let wg_v1176 = eval.m31_add(wg_v1173, wg_v1175);
    let wg_v1177 = eval.felt_get_m31(&wg_v1123, 23);
    let wg_v1178 = eval.m31_mul(wg_v1177, m31_262144);
    let wg_v1179 = eval.m31_add(wg_v1176, wg_v1178);
    let wg_v1180 = eval.felt_get_m31(&wg_v1123, 24);
    let wg_v1181 = eval.felt_get_m31(&wg_v1123, 25);
    let wg_v1182 = eval.m31_mul(wg_v1181, m31_512);
    let wg_v1183 = eval.m31_add(wg_v1180, wg_v1182);
    let wg_v1184 = eval.felt_get_m31(&wg_v1123, 26);
    let wg_v1185 = eval.m31_mul(wg_v1184, m31_262144);
    let wg_v1186 = eval.m31_add(wg_v1183, wg_v1185);
    let wg_v1187 = eval.felt_get_m31(&wg_v1123, 27);
    let combination_tmp_8c14f_49 = [
        wg_v1130, wg_v1137, wg_v1144, wg_v1151, wg_v1158, wg_v1165, wg_v1172, wg_v1179, wg_v1186,
        wg_v1187,
    ];
    let combination_limb_0_col125 = combination_tmp_8c14f_49[0];
    eval.set_col(125, combination_limb_0_col125);
    let combination_limb_1_col126 = combination_tmp_8c14f_49[1];
    eval.set_col(126, combination_limb_1_col126);
    let combination_limb_2_col127 = combination_tmp_8c14f_49[2];
    eval.set_col(127, combination_limb_2_col127);
    let combination_limb_3_col128 = combination_tmp_8c14f_49[3];
    eval.set_col(128, combination_limb_3_col128);
    let combination_limb_4_col129 = combination_tmp_8c14f_49[4];
    eval.set_col(129, combination_limb_4_col129);
    let combination_limb_5_col130 = combination_tmp_8c14f_49[5];
    eval.set_col(130, combination_limb_5_col130);
    let combination_limb_6_col131 = combination_tmp_8c14f_49[6];
    eval.set_col(131, combination_limb_6_col131);
    let combination_limb_7_col132 = combination_tmp_8c14f_49[7];
    eval.set_col(132, combination_limb_7_col132);
    let combination_limb_8_col133 = combination_tmp_8c14f_49[8];
    eval.set_col(133, combination_limb_8_col133);
    let combination_limb_9_col134 = combination_tmp_8c14f_49[9];
    eval.set_col(134, combination_limb_9_col134);
    let wg_v1188 = eval.m31_mul(m31_2, combination_limb_0_col114);
    let wg_v1189 = eval.m31_sub(wg_v1188, combination_limb_0_col125);
    let wg_v1190 = eval.m31_add(wg_v1189, m31_134217729);
    let biased_limb_accumulator_u32_tmp_8c14f_50 = eval.u32_from_m31(wg_v1190);
    let wg_v1191 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_50);
    let wg_v1192 = eval.u16_as_m31(wg_v1191);
    let p_coef_col135 = eval.m31_sub(wg_v1192, m31_1);
    eval.set_col(135, p_coef_col135);
    let wg_v1193 = eval.m31_mul(m31_2, combination_limb_0_col114);
    let wg_v1194 = eval.m31_sub(wg_v1193, combination_limb_0_col125);
    let wg_v1195 = eval.m31_sub(wg_v1194, p_coef_col135);
    let carry_0_tmp_8c14f_51 = eval.m31_mul(wg_v1195, m31_16);
    let wg_v1196 = eval.m31_mul(m31_2, combination_limb_1_col115);
    let wg_v1197 = eval.m31_add(carry_0_tmp_8c14f_51, wg_v1196);
    let wg_v1198 = eval.m31_sub(wg_v1197, combination_limb_1_col126);
    let carry_1_tmp_8c14f_52 = eval.m31_mul(wg_v1198, m31_16);
    let wg_v1199 = eval.m31_mul(m31_2, combination_limb_2_col116);
    let wg_v1200 = eval.m31_add(carry_1_tmp_8c14f_52, wg_v1199);
    let wg_v1201 = eval.m31_sub(wg_v1200, combination_limb_2_col127);
    let carry_2_tmp_8c14f_53 = eval.m31_mul(wg_v1201, m31_16);
    let wg_v1202 = eval.m31_mul(m31_2, combination_limb_3_col117);
    let wg_v1203 = eval.m31_add(carry_2_tmp_8c14f_53, wg_v1202);
    let wg_v1204 = eval.m31_sub(wg_v1203, combination_limb_3_col128);
    let carry_3_tmp_8c14f_54 = eval.m31_mul(wg_v1204, m31_16);
    let wg_v1205 = eval.m31_mul(m31_2, combination_limb_4_col118);
    let wg_v1206 = eval.m31_add(carry_3_tmp_8c14f_54, wg_v1205);
    let wg_v1207 = eval.m31_sub(wg_v1206, combination_limb_4_col129);
    let carry_4_tmp_8c14f_55 = eval.m31_mul(wg_v1207, m31_16);
    let wg_v1208 = eval.m31_mul(m31_2, combination_limb_5_col119);
    let wg_v1209 = eval.m31_add(carry_4_tmp_8c14f_55, wg_v1208);
    let wg_v1210 = eval.m31_sub(wg_v1209, combination_limb_5_col130);
    let carry_5_tmp_8c14f_56 = eval.m31_mul(wg_v1210, m31_16);
    let wg_v1211 = eval.m31_mul(m31_2, combination_limb_6_col120);
    let wg_v1212 = eval.m31_add(carry_5_tmp_8c14f_56, wg_v1211);
    let wg_v1213 = eval.m31_sub(wg_v1212, combination_limb_6_col131);
    let carry_6_tmp_8c14f_57 = eval.m31_mul(wg_v1213, m31_16);
    let wg_v1214 = eval.m31_mul(m31_2, combination_limb_7_col121);
    let wg_v1215 = eval.m31_add(carry_6_tmp_8c14f_57, wg_v1214);
    let wg_v1216 = eval.m31_sub(wg_v1215, combination_limb_7_col132);
    let wg_v1217 = eval.m31_mul(p_coef_col135, m31_136);
    let wg_v1218 = eval.m31_sub(wg_v1216, wg_v1217);
    let carry_7_tmp_8c14f_58 = eval.m31_mul(wg_v1218, m31_16);
    let wg_v1219 = eval.m31_mul(m31_2, combination_limb_8_col122);
    let wg_v1220 = eval.m31_add(carry_7_tmp_8c14f_58, wg_v1219);
    let wg_v1221 = eval.m31_sub(wg_v1220, combination_limb_8_col133);
    let carry_8_tmp_8c14f_59 = eval.m31_mul(wg_v1221, m31_16);
    let linear_combination_n_1_coefs_2_output_tmp_8c14f_69 = combination_tmp_8c14f_49;
    let poseidon_partial_round_output_tmp_8c14f_70 = [
        cube_252_output_tmp_8c14f_36,
        linear_combination_n_1_coefs_2_output_tmp_8c14f_69,
    ];
    let wg_v1222 = poseidon_partial_round_output_tmp_8c14f_70[1];
    let wg_v1223 = wg_v1222[0];
    let wg_v1224 = wg_v1222[1];
    let wg_v1225 = wg_v1222[2];
    let wg_v1226 = wg_v1222[3];
    let wg_v1227 = wg_v1222[4];
    let wg_v1228 = wg_v1222[5];
    let wg_v1229 = wg_v1222[6];
    let wg_v1230 = wg_v1222[7];
    let wg_v1231 = wg_v1222[8];
    let wg_v1232 = wg_v1222[9];
    eval.set_sub_input_word(21, wg_v1223);
    eval.set_sub_input_word(22, wg_v1224);
    eval.set_sub_input_word(23, wg_v1225);
    eval.set_sub_input_word(24, wg_v1226);
    eval.set_sub_input_word(25, wg_v1227);
    eval.set_sub_input_word(26, wg_v1228);
    eval.set_sub_input_word(27, wg_v1229);
    eval.set_sub_input_word(28, wg_v1230);
    eval.set_sub_input_word(29, wg_v1231);
    eval.set_sub_input_word(30, wg_v1232);
    let cube_252_output_tmp_8c14f_71 =
        eval.deduce_cube_252(poseidon_partial_round_output_tmp_8c14f_70[1]);
    let cube_252_output_limb_0_col136 = cube_252_output_tmp_8c14f_71[0];
    eval.set_col(136, cube_252_output_limb_0_col136);
    let cube_252_output_limb_1_col137 = cube_252_output_tmp_8c14f_71[1];
    eval.set_col(137, cube_252_output_limb_1_col137);
    let cube_252_output_limb_2_col138 = cube_252_output_tmp_8c14f_71[2];
    eval.set_col(138, cube_252_output_limb_2_col138);
    let cube_252_output_limb_3_col139 = cube_252_output_tmp_8c14f_71[3];
    eval.set_col(139, cube_252_output_limb_3_col139);
    let cube_252_output_limb_4_col140 = cube_252_output_tmp_8c14f_71[4];
    eval.set_col(140, cube_252_output_limb_4_col140);
    let cube_252_output_limb_5_col141 = cube_252_output_tmp_8c14f_71[5];
    eval.set_col(141, cube_252_output_limb_5_col141);
    let cube_252_output_limb_6_col142 = cube_252_output_tmp_8c14f_71[6];
    eval.set_col(142, cube_252_output_limb_6_col142);
    let cube_252_output_limb_7_col143 = cube_252_output_tmp_8c14f_71[7];
    eval.set_col(143, cube_252_output_limb_7_col143);
    let cube_252_output_limb_8_col144 = cube_252_output_tmp_8c14f_71[8];
    eval.set_col(144, cube_252_output_limb_8_col144);
    let cube_252_output_limb_9_col145 = cube_252_output_tmp_8c14f_71[9];
    eval.set_col(145, cube_252_output_limb_9_col145);
    eval.set_lookup_word(122, m31_1987997202);
    eval.set_lookup_word(123, combination_limb_0_col125);
    eval.set_lookup_word(124, combination_limb_1_col126);
    eval.set_lookup_word(125, combination_limb_2_col127);
    eval.set_lookup_word(126, combination_limb_3_col128);
    eval.set_lookup_word(127, combination_limb_4_col129);
    eval.set_lookup_word(128, combination_limb_5_col130);
    eval.set_lookup_word(129, combination_limb_6_col131);
    eval.set_lookup_word(130, combination_limb_7_col132);
    eval.set_lookup_word(131, combination_limb_8_col133);
    eval.set_lookup_word(132, combination_limb_9_col134);
    eval.set_lookup_word(133, cube_252_output_limb_0_col136);
    eval.set_lookup_word(134, cube_252_output_limb_1_col137);
    eval.set_lookup_word(135, cube_252_output_limb_2_col138);
    eval.set_lookup_word(136, cube_252_output_limb_3_col139);
    eval.set_lookup_word(137, cube_252_output_limb_4_col140);
    eval.set_lookup_word(138, cube_252_output_limb_5_col141);
    eval.set_lookup_word(139, cube_252_output_limb_6_col142);
    eval.set_lookup_word(140, cube_252_output_limb_7_col143);
    eval.set_lookup_word(141, cube_252_output_limb_8_col144);
    eval.set_lookup_word(142, cube_252_output_limb_9_col145);
    let wg_v1233 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1234 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1235 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_35[0]);
    let wg_v1236 = eval.felt_from_limbs([
        m31_4, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1237 = eval.felt_mul(wg_v1236.clone(), wg_v1235.clone());
    let wg_v1238 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1239 = eval.felt_add(wg_v1238.clone(), wg_v1237.clone());
    let wg_v1240 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1241 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_35[1]);
    let wg_v1242 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1243 = eval.felt_mul(wg_v1242.clone(), wg_v1241.clone());
    let wg_v1244 = eval.felt_add(wg_v1239.clone(), wg_v1243.clone());
    let wg_v1245 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1246 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_70[0]);
    let wg_v1247 = eval.felt_from_limbs([
        m31_3, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1248 = eval.felt_mul(wg_v1247.clone(), wg_v1246.clone());
    let wg_v1249 = eval.felt_add(wg_v1244.clone(), wg_v1248.clone());
    let wg_v1250 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1251 = eval.felt_from_w27_words(poseidon_partial_round_output_tmp_8c14f_70[1]);
    let wg_v1252 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1253 = eval.felt_mul(wg_v1252.clone(), wg_v1251.clone());
    let wg_v1254 = eval.felt_add(wg_v1249.clone(), wg_v1253.clone());
    let wg_v1255 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1256 = eval.felt_from_w27_words(cube_252_output_tmp_8c14f_71);
    let wg_v1257 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1258 = eval.felt_mul(wg_v1257.clone(), wg_v1256.clone());
    let wg_v1259 = eval.felt_sub(wg_v1254.clone(), wg_v1258.clone());
    let wg_v1260 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1261 = eval.felt_from_w27_words(poseidon_round_keys_output_tmp_8c14f_0[2]);
    let wg_v1262 = eval.felt_from_limbs([
        m31_1, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1263 = eval.felt_mul(wg_v1262.clone(), wg_v1261.clone());
    let wg_v1264 = eval.felt_add(wg_v1259.clone(), wg_v1263.clone());
    let wg_v1265 = eval.felt_get_m31(&wg_v1264, 0);
    let wg_v1266 = eval.felt_get_m31(&wg_v1264, 1);
    let wg_v1267 = eval.m31_mul(wg_v1266, m31_512);
    let wg_v1268 = eval.m31_add(wg_v1265, wg_v1267);
    let wg_v1269 = eval.felt_get_m31(&wg_v1264, 2);
    let wg_v1270 = eval.m31_mul(wg_v1269, m31_262144);
    let wg_v1271 = eval.m31_add(wg_v1268, wg_v1270);
    let wg_v1272 = eval.felt_get_m31(&wg_v1264, 3);
    let wg_v1273 = eval.felt_get_m31(&wg_v1264, 4);
    let wg_v1274 = eval.m31_mul(wg_v1273, m31_512);
    let wg_v1275 = eval.m31_add(wg_v1272, wg_v1274);
    let wg_v1276 = eval.felt_get_m31(&wg_v1264, 5);
    let wg_v1277 = eval.m31_mul(wg_v1276, m31_262144);
    let wg_v1278 = eval.m31_add(wg_v1275, wg_v1277);
    let wg_v1279 = eval.felt_get_m31(&wg_v1264, 6);
    let wg_v1280 = eval.felt_get_m31(&wg_v1264, 7);
    let wg_v1281 = eval.m31_mul(wg_v1280, m31_512);
    let wg_v1282 = eval.m31_add(wg_v1279, wg_v1281);
    let wg_v1283 = eval.felt_get_m31(&wg_v1264, 8);
    let wg_v1284 = eval.m31_mul(wg_v1283, m31_262144);
    let wg_v1285 = eval.m31_add(wg_v1282, wg_v1284);
    let wg_v1286 = eval.felt_get_m31(&wg_v1264, 9);
    let wg_v1287 = eval.felt_get_m31(&wg_v1264, 10);
    let wg_v1288 = eval.m31_mul(wg_v1287, m31_512);
    let wg_v1289 = eval.m31_add(wg_v1286, wg_v1288);
    let wg_v1290 = eval.felt_get_m31(&wg_v1264, 11);
    let wg_v1291 = eval.m31_mul(wg_v1290, m31_262144);
    let wg_v1292 = eval.m31_add(wg_v1289, wg_v1291);
    let wg_v1293 = eval.felt_get_m31(&wg_v1264, 12);
    let wg_v1294 = eval.felt_get_m31(&wg_v1264, 13);
    let wg_v1295 = eval.m31_mul(wg_v1294, m31_512);
    let wg_v1296 = eval.m31_add(wg_v1293, wg_v1295);
    let wg_v1297 = eval.felt_get_m31(&wg_v1264, 14);
    let wg_v1298 = eval.m31_mul(wg_v1297, m31_262144);
    let wg_v1299 = eval.m31_add(wg_v1296, wg_v1298);
    let wg_v1300 = eval.felt_get_m31(&wg_v1264, 15);
    let wg_v1301 = eval.felt_get_m31(&wg_v1264, 16);
    let wg_v1302 = eval.m31_mul(wg_v1301, m31_512);
    let wg_v1303 = eval.m31_add(wg_v1300, wg_v1302);
    let wg_v1304 = eval.felt_get_m31(&wg_v1264, 17);
    let wg_v1305 = eval.m31_mul(wg_v1304, m31_262144);
    let wg_v1306 = eval.m31_add(wg_v1303, wg_v1305);
    let wg_v1307 = eval.felt_get_m31(&wg_v1264, 18);
    let wg_v1308 = eval.felt_get_m31(&wg_v1264, 19);
    let wg_v1309 = eval.m31_mul(wg_v1308, m31_512);
    let wg_v1310 = eval.m31_add(wg_v1307, wg_v1309);
    let wg_v1311 = eval.felt_get_m31(&wg_v1264, 20);
    let wg_v1312 = eval.m31_mul(wg_v1311, m31_262144);
    let wg_v1313 = eval.m31_add(wg_v1310, wg_v1312);
    let wg_v1314 = eval.felt_get_m31(&wg_v1264, 21);
    let wg_v1315 = eval.felt_get_m31(&wg_v1264, 22);
    let wg_v1316 = eval.m31_mul(wg_v1315, m31_512);
    let wg_v1317 = eval.m31_add(wg_v1314, wg_v1316);
    let wg_v1318 = eval.felt_get_m31(&wg_v1264, 23);
    let wg_v1319 = eval.m31_mul(wg_v1318, m31_262144);
    let wg_v1320 = eval.m31_add(wg_v1317, wg_v1319);
    let wg_v1321 = eval.felt_get_m31(&wg_v1264, 24);
    let wg_v1322 = eval.felt_get_m31(&wg_v1264, 25);
    let wg_v1323 = eval.m31_mul(wg_v1322, m31_512);
    let wg_v1324 = eval.m31_add(wg_v1321, wg_v1323);
    let wg_v1325 = eval.felt_get_m31(&wg_v1264, 26);
    let wg_v1326 = eval.m31_mul(wg_v1325, m31_262144);
    let wg_v1327 = eval.m31_add(wg_v1324, wg_v1326);
    let wg_v1328 = eval.felt_get_m31(&wg_v1264, 27);
    let combination_tmp_8c14f_72 = [
        wg_v1271, wg_v1278, wg_v1285, wg_v1292, wg_v1299, wg_v1306, wg_v1313, wg_v1320, wg_v1327,
        wg_v1328,
    ];
    let combination_limb_0_col146 = combination_tmp_8c14f_72[0];
    eval.set_col(146, combination_limb_0_col146);
    let combination_limb_1_col147 = combination_tmp_8c14f_72[1];
    eval.set_col(147, combination_limb_1_col147);
    let combination_limb_2_col148 = combination_tmp_8c14f_72[2];
    eval.set_col(148, combination_limb_2_col148);
    let combination_limb_3_col149 = combination_tmp_8c14f_72[3];
    eval.set_col(149, combination_limb_3_col149);
    let combination_limb_4_col150 = combination_tmp_8c14f_72[4];
    eval.set_col(150, combination_limb_4_col150);
    let combination_limb_5_col151 = combination_tmp_8c14f_72[5];
    eval.set_col(151, combination_limb_5_col151);
    let combination_limb_6_col152 = combination_tmp_8c14f_72[6];
    eval.set_col(152, combination_limb_6_col152);
    let combination_limb_7_col153 = combination_tmp_8c14f_72[7];
    eval.set_col(153, combination_limb_7_col153);
    let combination_limb_8_col154 = combination_tmp_8c14f_72[8];
    eval.set_col(154, combination_limb_8_col154);
    let combination_limb_9_col155 = combination_tmp_8c14f_72[9];
    eval.set_col(155, combination_limb_9_col155);
    let wg_v1329 = eval.m31_mul(m31_4, cube_252_output_limb_0_col72);
    let wg_v1330 = eval.m31_mul(m31_2, combination_limb_0_col93);
    let wg_v1331 = eval.m31_add(wg_v1329, wg_v1330);
    let wg_v1332 = eval.m31_mul(m31_3, cube_252_output_limb_0_col104);
    let wg_v1333 = eval.m31_add(wg_v1331, wg_v1332);
    let wg_v1334 = eval.m31_add(wg_v1333, combination_limb_0_col125);
    let wg_v1335 = eval.m31_sub(wg_v1334, cube_252_output_limb_0_col136);
    let wg_v1336 = eval.m31_add(wg_v1335, poseidon_round_keys_output_limb_20_col62);
    let wg_v1337 = eval.m31_sub(wg_v1336, combination_limb_0_col146);
    let wg_v1338 = eval.m31_add(wg_v1337, m31_268435458);
    let biased_limb_accumulator_u32_tmp_8c14f_73 = eval.u32_from_m31(wg_v1338);
    let wg_v1339 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_73);
    let wg_v1340 = eval.u16_as_m31(wg_v1339);
    let p_coef_col156 = eval.m31_sub(wg_v1340, m31_2);
    eval.set_col(156, p_coef_col156);
    let wg_v1341 = eval.m31_mul(m31_4, cube_252_output_limb_0_col72);
    let wg_v1342 = eval.m31_mul(m31_2, combination_limb_0_col93);
    let wg_v1343 = eval.m31_add(wg_v1341, wg_v1342);
    let wg_v1344 = eval.m31_mul(m31_3, cube_252_output_limb_0_col104);
    let wg_v1345 = eval.m31_add(wg_v1343, wg_v1344);
    let wg_v1346 = eval.m31_add(wg_v1345, combination_limb_0_col125);
    let wg_v1347 = eval.m31_sub(wg_v1346, cube_252_output_limb_0_col136);
    let wg_v1348 = eval.m31_add(wg_v1347, poseidon_round_keys_output_limb_20_col62);
    let wg_v1349 = eval.m31_sub(wg_v1348, combination_limb_0_col146);
    let wg_v1350 = eval.m31_sub(wg_v1349, p_coef_col156);
    let carry_0_tmp_8c14f_74 = eval.m31_mul(wg_v1350, m31_16);
    let wg_v1351 = eval.m31_mul(m31_4, cube_252_output_limb_1_col73);
    let wg_v1352 = eval.m31_add(carry_0_tmp_8c14f_74, wg_v1351);
    let wg_v1353 = eval.m31_mul(m31_2, combination_limb_1_col94);
    let wg_v1354 = eval.m31_add(wg_v1352, wg_v1353);
    let wg_v1355 = eval.m31_mul(m31_3, cube_252_output_limb_1_col105);
    let wg_v1356 = eval.m31_add(wg_v1354, wg_v1355);
    let wg_v1357 = eval.m31_add(wg_v1356, combination_limb_1_col126);
    let wg_v1358 = eval.m31_sub(wg_v1357, cube_252_output_limb_1_col137);
    let wg_v1359 = eval.m31_add(wg_v1358, poseidon_round_keys_output_limb_21_col63);
    let wg_v1360 = eval.m31_sub(wg_v1359, combination_limb_1_col147);
    let carry_1_tmp_8c14f_75 = eval.m31_mul(wg_v1360, m31_16);
    let wg_v1361 = eval.m31_mul(m31_4, cube_252_output_limb_2_col74);
    let wg_v1362 = eval.m31_add(carry_1_tmp_8c14f_75, wg_v1361);
    let wg_v1363 = eval.m31_mul(m31_2, combination_limb_2_col95);
    let wg_v1364 = eval.m31_add(wg_v1362, wg_v1363);
    let wg_v1365 = eval.m31_mul(m31_3, cube_252_output_limb_2_col106);
    let wg_v1366 = eval.m31_add(wg_v1364, wg_v1365);
    let wg_v1367 = eval.m31_add(wg_v1366, combination_limb_2_col127);
    let wg_v1368 = eval.m31_sub(wg_v1367, cube_252_output_limb_2_col138);
    let wg_v1369 = eval.m31_add(wg_v1368, poseidon_round_keys_output_limb_22_col64);
    let wg_v1370 = eval.m31_sub(wg_v1369, combination_limb_2_col148);
    let carry_2_tmp_8c14f_76 = eval.m31_mul(wg_v1370, m31_16);
    let wg_v1371 = eval.m31_mul(m31_4, cube_252_output_limb_3_col75);
    let wg_v1372 = eval.m31_add(carry_2_tmp_8c14f_76, wg_v1371);
    let wg_v1373 = eval.m31_mul(m31_2, combination_limb_3_col96);
    let wg_v1374 = eval.m31_add(wg_v1372, wg_v1373);
    let wg_v1375 = eval.m31_mul(m31_3, cube_252_output_limb_3_col107);
    let wg_v1376 = eval.m31_add(wg_v1374, wg_v1375);
    let wg_v1377 = eval.m31_add(wg_v1376, combination_limb_3_col128);
    let wg_v1378 = eval.m31_sub(wg_v1377, cube_252_output_limb_3_col139);
    let wg_v1379 = eval.m31_add(wg_v1378, poseidon_round_keys_output_limb_23_col65);
    let wg_v1380 = eval.m31_sub(wg_v1379, combination_limb_3_col149);
    let carry_3_tmp_8c14f_77 = eval.m31_mul(wg_v1380, m31_16);
    let wg_v1381 = eval.m31_mul(m31_4, cube_252_output_limb_4_col76);
    let wg_v1382 = eval.m31_add(carry_3_tmp_8c14f_77, wg_v1381);
    let wg_v1383 = eval.m31_mul(m31_2, combination_limb_4_col97);
    let wg_v1384 = eval.m31_add(wg_v1382, wg_v1383);
    let wg_v1385 = eval.m31_mul(m31_3, cube_252_output_limb_4_col108);
    let wg_v1386 = eval.m31_add(wg_v1384, wg_v1385);
    let wg_v1387 = eval.m31_add(wg_v1386, combination_limb_4_col129);
    let wg_v1388 = eval.m31_sub(wg_v1387, cube_252_output_limb_4_col140);
    let wg_v1389 = eval.m31_add(wg_v1388, poseidon_round_keys_output_limb_24_col66);
    let wg_v1390 = eval.m31_sub(wg_v1389, combination_limb_4_col150);
    let carry_4_tmp_8c14f_78 = eval.m31_mul(wg_v1390, m31_16);
    let wg_v1391 = eval.m31_mul(m31_4, cube_252_output_limb_5_col77);
    let wg_v1392 = eval.m31_add(carry_4_tmp_8c14f_78, wg_v1391);
    let wg_v1393 = eval.m31_mul(m31_2, combination_limb_5_col98);
    let wg_v1394 = eval.m31_add(wg_v1392, wg_v1393);
    let wg_v1395 = eval.m31_mul(m31_3, cube_252_output_limb_5_col109);
    let wg_v1396 = eval.m31_add(wg_v1394, wg_v1395);
    let wg_v1397 = eval.m31_add(wg_v1396, combination_limb_5_col130);
    let wg_v1398 = eval.m31_sub(wg_v1397, cube_252_output_limb_5_col141);
    let wg_v1399 = eval.m31_add(wg_v1398, poseidon_round_keys_output_limb_25_col67);
    let wg_v1400 = eval.m31_sub(wg_v1399, combination_limb_5_col151);
    let carry_5_tmp_8c14f_79 = eval.m31_mul(wg_v1400, m31_16);
    let wg_v1401 = eval.m31_mul(m31_4, cube_252_output_limb_6_col78);
    let wg_v1402 = eval.m31_add(carry_5_tmp_8c14f_79, wg_v1401);
    let wg_v1403 = eval.m31_mul(m31_2, combination_limb_6_col99);
    let wg_v1404 = eval.m31_add(wg_v1402, wg_v1403);
    let wg_v1405 = eval.m31_mul(m31_3, cube_252_output_limb_6_col110);
    let wg_v1406 = eval.m31_add(wg_v1404, wg_v1405);
    let wg_v1407 = eval.m31_add(wg_v1406, combination_limb_6_col131);
    let wg_v1408 = eval.m31_sub(wg_v1407, cube_252_output_limb_6_col142);
    let wg_v1409 = eval.m31_add(wg_v1408, poseidon_round_keys_output_limb_26_col68);
    let wg_v1410 = eval.m31_sub(wg_v1409, combination_limb_6_col152);
    let carry_6_tmp_8c14f_80 = eval.m31_mul(wg_v1410, m31_16);
    let wg_v1411 = eval.m31_mul(m31_4, cube_252_output_limb_7_col79);
    let wg_v1412 = eval.m31_add(carry_6_tmp_8c14f_80, wg_v1411);
    let wg_v1413 = eval.m31_mul(m31_2, combination_limb_7_col100);
    let wg_v1414 = eval.m31_add(wg_v1412, wg_v1413);
    let wg_v1415 = eval.m31_mul(m31_3, cube_252_output_limb_7_col111);
    let wg_v1416 = eval.m31_add(wg_v1414, wg_v1415);
    let wg_v1417 = eval.m31_add(wg_v1416, combination_limb_7_col132);
    let wg_v1418 = eval.m31_sub(wg_v1417, cube_252_output_limb_7_col143);
    let wg_v1419 = eval.m31_add(wg_v1418, poseidon_round_keys_output_limb_27_col69);
    let wg_v1420 = eval.m31_sub(wg_v1419, combination_limb_7_col153);
    let wg_v1421 = eval.m31_mul(p_coef_col156, m31_136);
    let wg_v1422 = eval.m31_sub(wg_v1420, wg_v1421);
    let carry_7_tmp_8c14f_81 = eval.m31_mul(wg_v1422, m31_16);
    let wg_v1423 = eval.m31_mul(m31_4, cube_252_output_limb_8_col80);
    let wg_v1424 = eval.m31_add(carry_7_tmp_8c14f_81, wg_v1423);
    let wg_v1425 = eval.m31_mul(m31_2, combination_limb_8_col101);
    let wg_v1426 = eval.m31_add(wg_v1424, wg_v1425);
    let wg_v1427 = eval.m31_mul(m31_3, cube_252_output_limb_8_col112);
    let wg_v1428 = eval.m31_add(wg_v1426, wg_v1427);
    let wg_v1429 = eval.m31_add(wg_v1428, combination_limb_8_col133);
    let wg_v1430 = eval.m31_sub(wg_v1429, cube_252_output_limb_8_col144);
    let wg_v1431 = eval.m31_add(wg_v1430, poseidon_round_keys_output_limb_28_col70);
    let wg_v1432 = eval.m31_sub(wg_v1431, combination_limb_8_col154);
    let carry_8_tmp_8c14f_82 = eval.m31_mul(wg_v1432, m31_16);
    let wg_v1433 = eval.m31_add(p_coef_col156, m31_2);
    let wg_v1434 = eval.m31_add(carry_0_tmp_8c14f_74, m31_2);
    let wg_v1435 = eval.m31_add(carry_1_tmp_8c14f_75, m31_2);
    let wg_v1436 = eval.m31_add(carry_2_tmp_8c14f_76, m31_2);
    eval.set_sub_input_word(47, wg_v1433);
    eval.set_sub_input_word(48, wg_v1434);
    eval.set_sub_input_word(49, wg_v1435);
    eval.set_sub_input_word(50, wg_v1436);
    eval.set_lookup_word(143, m31_1027333874);
    let wg_v1437 = eval.m31_add(p_coef_col156, m31_2);
    eval.set_lookup_word(144, wg_v1437);
    let wg_v1438 = eval.m31_add(carry_0_tmp_8c14f_74, m31_2);
    eval.set_lookup_word(145, wg_v1438);
    let wg_v1439 = eval.m31_add(carry_1_tmp_8c14f_75, m31_2);
    eval.set_lookup_word(146, wg_v1439);
    let wg_v1440 = eval.m31_add(carry_2_tmp_8c14f_76, m31_2);
    eval.set_lookup_word(147, wg_v1440);
    let wg_v1441 = eval.m31_add(carry_3_tmp_8c14f_77, m31_2);
    let wg_v1442 = eval.m31_add(carry_4_tmp_8c14f_78, m31_2);
    let wg_v1443 = eval.m31_add(carry_5_tmp_8c14f_79, m31_2);
    let wg_v1444 = eval.m31_add(carry_6_tmp_8c14f_80, m31_2);
    eval.set_sub_input_word(51, wg_v1441);
    eval.set_sub_input_word(52, wg_v1442);
    eval.set_sub_input_word(53, wg_v1443);
    eval.set_sub_input_word(54, wg_v1444);
    eval.set_lookup_word(148, m31_1027333874);
    let wg_v1445 = eval.m31_add(carry_3_tmp_8c14f_77, m31_2);
    eval.set_lookup_word(149, wg_v1445);
    let wg_v1446 = eval.m31_add(carry_4_tmp_8c14f_78, m31_2);
    eval.set_lookup_word(150, wg_v1446);
    let wg_v1447 = eval.m31_add(carry_5_tmp_8c14f_79, m31_2);
    eval.set_lookup_word(151, wg_v1447);
    let wg_v1448 = eval.m31_add(carry_6_tmp_8c14f_80, m31_2);
    eval.set_lookup_word(152, wg_v1448);
    let wg_v1449 = eval.m31_add(carry_7_tmp_8c14f_81, m31_2);
    let wg_v1450 = eval.m31_add(carry_8_tmp_8c14f_82, m31_2);
    eval.set_sub_input_word(59, wg_v1449);
    eval.set_sub_input_word(60, wg_v1450);
    eval.set_lookup_word(153, m31_1651211826);
    let wg_v1451 = eval.m31_add(carry_7_tmp_8c14f_81, m31_2);
    eval.set_lookup_word(154, wg_v1451);
    let wg_v1452 = eval.m31_add(carry_8_tmp_8c14f_82, m31_2);
    eval.set_lookup_word(155, wg_v1452);
    let linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83 = combination_tmp_8c14f_72;
    let wg_v1453 = linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83;
    let wg_v1454 = wg_v1453[0];
    let wg_v1455 = wg_v1453[1];
    let wg_v1456 = wg_v1453[2];
    let wg_v1457 = wg_v1453[3];
    let wg_v1458 = wg_v1453[4];
    let wg_v1459 = wg_v1453[5];
    let wg_v1460 = wg_v1453[6];
    let wg_v1461 = wg_v1453[7];
    let wg_v1462 = wg_v1453[8];
    let wg_v1463 = wg_v1453[9];
    eval.set_sub_input_word(81, wg_v1454);
    eval.set_sub_input_word(82, wg_v1455);
    eval.set_sub_input_word(83, wg_v1456);
    eval.set_sub_input_word(84, wg_v1457);
    eval.set_sub_input_word(85, wg_v1458);
    eval.set_sub_input_word(86, wg_v1459);
    eval.set_sub_input_word(87, wg_v1460);
    eval.set_sub_input_word(88, wg_v1461);
    eval.set_sub_input_word(89, wg_v1462);
    eval.set_sub_input_word(90, wg_v1463);
    eval.set_lookup_word(156, m31_1090315331);
    eval.set_lookup_word(157, combination_limb_0_col146);
    eval.set_lookup_word(158, combination_limb_1_col147);
    eval.set_lookup_word(159, combination_limb_2_col148);
    eval.set_lookup_word(160, combination_limb_3_col149);
    eval.set_lookup_word(161, combination_limb_4_col150);
    eval.set_lookup_word(162, combination_limb_5_col151);
    eval.set_lookup_word(163, combination_limb_6_col152);
    eval.set_lookup_word(164, combination_limb_7_col153);
    eval.set_lookup_word(165, combination_limb_8_col154);
    eval.set_lookup_word(166, combination_limb_9_col155);
    let wg_v1464 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1465 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1466 =
        eval.felt_from_w27_words(linear_combination_n_6_coefs_4_2_3_1_m1_1_output_tmp_8c14f_83);
    let wg_v1467 = eval.felt_from_limbs([
        m31_2, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1468 = eval.felt_mul(wg_v1467.clone(), wg_v1466.clone());
    let wg_v1469 = eval.felt_from_limbs([
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0, m31_0,
        m31_0, m31_0,
    ]);
    let wg_v1470 = eval.felt_add(wg_v1469.clone(), wg_v1468.clone());
    let wg_v1471 = eval.felt_get_m31(&wg_v1470, 0);
    let wg_v1472 = eval.felt_get_m31(&wg_v1470, 1);
    let wg_v1473 = eval.m31_mul(wg_v1472, m31_512);
    let wg_v1474 = eval.m31_add(wg_v1471, wg_v1473);
    let wg_v1475 = eval.felt_get_m31(&wg_v1470, 2);
    let wg_v1476 = eval.m31_mul(wg_v1475, m31_262144);
    let wg_v1477 = eval.m31_add(wg_v1474, wg_v1476);
    let wg_v1478 = eval.felt_get_m31(&wg_v1470, 3);
    let wg_v1479 = eval.felt_get_m31(&wg_v1470, 4);
    let wg_v1480 = eval.m31_mul(wg_v1479, m31_512);
    let wg_v1481 = eval.m31_add(wg_v1478, wg_v1480);
    let wg_v1482 = eval.felt_get_m31(&wg_v1470, 5);
    let wg_v1483 = eval.m31_mul(wg_v1482, m31_262144);
    let wg_v1484 = eval.m31_add(wg_v1481, wg_v1483);
    let wg_v1485 = eval.felt_get_m31(&wg_v1470, 6);
    let wg_v1486 = eval.felt_get_m31(&wg_v1470, 7);
    let wg_v1487 = eval.m31_mul(wg_v1486, m31_512);
    let wg_v1488 = eval.m31_add(wg_v1485, wg_v1487);
    let wg_v1489 = eval.felt_get_m31(&wg_v1470, 8);
    let wg_v1490 = eval.m31_mul(wg_v1489, m31_262144);
    let wg_v1491 = eval.m31_add(wg_v1488, wg_v1490);
    let wg_v1492 = eval.felt_get_m31(&wg_v1470, 9);
    let wg_v1493 = eval.felt_get_m31(&wg_v1470, 10);
    let wg_v1494 = eval.m31_mul(wg_v1493, m31_512);
    let wg_v1495 = eval.m31_add(wg_v1492, wg_v1494);
    let wg_v1496 = eval.felt_get_m31(&wg_v1470, 11);
    let wg_v1497 = eval.m31_mul(wg_v1496, m31_262144);
    let wg_v1498 = eval.m31_add(wg_v1495, wg_v1497);
    let wg_v1499 = eval.felt_get_m31(&wg_v1470, 12);
    let wg_v1500 = eval.felt_get_m31(&wg_v1470, 13);
    let wg_v1501 = eval.m31_mul(wg_v1500, m31_512);
    let wg_v1502 = eval.m31_add(wg_v1499, wg_v1501);
    let wg_v1503 = eval.felt_get_m31(&wg_v1470, 14);
    let wg_v1504 = eval.m31_mul(wg_v1503, m31_262144);
    let wg_v1505 = eval.m31_add(wg_v1502, wg_v1504);
    let wg_v1506 = eval.felt_get_m31(&wg_v1470, 15);
    let wg_v1507 = eval.felt_get_m31(&wg_v1470, 16);
    let wg_v1508 = eval.m31_mul(wg_v1507, m31_512);
    let wg_v1509 = eval.m31_add(wg_v1506, wg_v1508);
    let wg_v1510 = eval.felt_get_m31(&wg_v1470, 17);
    let wg_v1511 = eval.m31_mul(wg_v1510, m31_262144);
    let wg_v1512 = eval.m31_add(wg_v1509, wg_v1511);
    let wg_v1513 = eval.felt_get_m31(&wg_v1470, 18);
    let wg_v1514 = eval.felt_get_m31(&wg_v1470, 19);
    let wg_v1515 = eval.m31_mul(wg_v1514, m31_512);
    let wg_v1516 = eval.m31_add(wg_v1513, wg_v1515);
    let wg_v1517 = eval.felt_get_m31(&wg_v1470, 20);
    let wg_v1518 = eval.m31_mul(wg_v1517, m31_262144);
    let wg_v1519 = eval.m31_add(wg_v1516, wg_v1518);
    let wg_v1520 = eval.felt_get_m31(&wg_v1470, 21);
    let wg_v1521 = eval.felt_get_m31(&wg_v1470, 22);
    let wg_v1522 = eval.m31_mul(wg_v1521, m31_512);
    let wg_v1523 = eval.m31_add(wg_v1520, wg_v1522);
    let wg_v1524 = eval.felt_get_m31(&wg_v1470, 23);
    let wg_v1525 = eval.m31_mul(wg_v1524, m31_262144);
    let wg_v1526 = eval.m31_add(wg_v1523, wg_v1525);
    let wg_v1527 = eval.felt_get_m31(&wg_v1470, 24);
    let wg_v1528 = eval.felt_get_m31(&wg_v1470, 25);
    let wg_v1529 = eval.m31_mul(wg_v1528, m31_512);
    let wg_v1530 = eval.m31_add(wg_v1527, wg_v1529);
    let wg_v1531 = eval.felt_get_m31(&wg_v1470, 26);
    let wg_v1532 = eval.m31_mul(wg_v1531, m31_262144);
    let wg_v1533 = eval.m31_add(wg_v1530, wg_v1532);
    let wg_v1534 = eval.felt_get_m31(&wg_v1470, 27);
    let combination_tmp_8c14f_84 = [
        wg_v1477, wg_v1484, wg_v1491, wg_v1498, wg_v1505, wg_v1512, wg_v1519, wg_v1526, wg_v1533,
        wg_v1534,
    ];
    let combination_limb_0_col157 = combination_tmp_8c14f_84[0];
    eval.set_col(157, combination_limb_0_col157);
    let combination_limb_1_col158 = combination_tmp_8c14f_84[1];
    eval.set_col(158, combination_limb_1_col158);
    let combination_limb_2_col159 = combination_tmp_8c14f_84[2];
    eval.set_col(159, combination_limb_2_col159);
    let combination_limb_3_col160 = combination_tmp_8c14f_84[3];
    eval.set_col(160, combination_limb_3_col160);
    let combination_limb_4_col161 = combination_tmp_8c14f_84[4];
    eval.set_col(161, combination_limb_4_col161);
    let combination_limb_5_col162 = combination_tmp_8c14f_84[5];
    eval.set_col(162, combination_limb_5_col162);
    let combination_limb_6_col163 = combination_tmp_8c14f_84[6];
    eval.set_col(163, combination_limb_6_col163);
    let combination_limb_7_col164 = combination_tmp_8c14f_84[7];
    eval.set_col(164, combination_limb_7_col164);
    let combination_limb_8_col165 = combination_tmp_8c14f_84[8];
    eval.set_col(165, combination_limb_8_col165);
    let combination_limb_9_col166 = combination_tmp_8c14f_84[9];
    eval.set_col(166, combination_limb_9_col166);
    let wg_v1535 = eval.m31_mul(m31_2, combination_limb_0_col146);
    let wg_v1536 = eval.m31_sub(wg_v1535, combination_limb_0_col157);
    let wg_v1537 = eval.m31_add(wg_v1536, m31_134217729);
    let biased_limb_accumulator_u32_tmp_8c14f_85 = eval.u32_from_m31(wg_v1537);
    let wg_v1538 = eval.u32_low(biased_limb_accumulator_u32_tmp_8c14f_85);
    let wg_v1539 = eval.u16_as_m31(wg_v1538);
    let p_coef_col167 = eval.m31_sub(wg_v1539, m31_1);
    eval.set_col(167, p_coef_col167);
    let wg_v1540 = eval.m31_mul(m31_2, combination_limb_0_col146);
    let wg_v1541 = eval.m31_sub(wg_v1540, combination_limb_0_col157);
    let wg_v1542 = eval.m31_sub(wg_v1541, p_coef_col167);
    let carry_0_tmp_8c14f_86 = eval.m31_mul(wg_v1542, m31_16);
    let wg_v1543 = eval.m31_mul(m31_2, combination_limb_1_col147);
    let wg_v1544 = eval.m31_add(carry_0_tmp_8c14f_86, wg_v1543);
    let wg_v1545 = eval.m31_sub(wg_v1544, combination_limb_1_col158);
    let carry_1_tmp_8c14f_87 = eval.m31_mul(wg_v1545, m31_16);
    let wg_v1546 = eval.m31_mul(m31_2, combination_limb_2_col148);
    let wg_v1547 = eval.m31_add(carry_1_tmp_8c14f_87, wg_v1546);
    let wg_v1548 = eval.m31_sub(wg_v1547, combination_limb_2_col159);
    let carry_2_tmp_8c14f_88 = eval.m31_mul(wg_v1548, m31_16);
    let wg_v1549 = eval.m31_mul(m31_2, combination_limb_3_col149);
    let wg_v1550 = eval.m31_add(carry_2_tmp_8c14f_88, wg_v1549);
    let wg_v1551 = eval.m31_sub(wg_v1550, combination_limb_3_col160);
    let carry_3_tmp_8c14f_89 = eval.m31_mul(wg_v1551, m31_16);
    let wg_v1552 = eval.m31_mul(m31_2, combination_limb_4_col150);
    let wg_v1553 = eval.m31_add(carry_3_tmp_8c14f_89, wg_v1552);
    let wg_v1554 = eval.m31_sub(wg_v1553, combination_limb_4_col161);
    let carry_4_tmp_8c14f_90 = eval.m31_mul(wg_v1554, m31_16);
    let wg_v1555 = eval.m31_mul(m31_2, combination_limb_5_col151);
    let wg_v1556 = eval.m31_add(carry_4_tmp_8c14f_90, wg_v1555);
    let wg_v1557 = eval.m31_sub(wg_v1556, combination_limb_5_col162);
    let carry_5_tmp_8c14f_91 = eval.m31_mul(wg_v1557, m31_16);
    let wg_v1558 = eval.m31_mul(m31_2, combination_limb_6_col152);
    let wg_v1559 = eval.m31_add(carry_5_tmp_8c14f_91, wg_v1558);
    let wg_v1560 = eval.m31_sub(wg_v1559, combination_limb_6_col163);
    let carry_6_tmp_8c14f_92 = eval.m31_mul(wg_v1560, m31_16);
    let wg_v1561 = eval.m31_mul(m31_2, combination_limb_7_col153);
    let wg_v1562 = eval.m31_add(carry_6_tmp_8c14f_92, wg_v1561);
    let wg_v1563 = eval.m31_sub(wg_v1562, combination_limb_7_col164);
    let wg_v1564 = eval.m31_mul(p_coef_col167, m31_136);
    let wg_v1565 = eval.m31_sub(wg_v1563, wg_v1564);
    let carry_7_tmp_8c14f_93 = eval.m31_mul(wg_v1565, m31_16);
    let wg_v1566 = eval.m31_mul(m31_2, combination_limb_8_col154);
    let wg_v1567 = eval.m31_add(carry_7_tmp_8c14f_93, wg_v1566);
    let wg_v1568 = eval.m31_sub(wg_v1567, combination_limb_8_col165);
    let carry_8_tmp_8c14f_94 = eval.m31_mul(wg_v1568, m31_16);
    let linear_combination_n_1_coefs_2_output_tmp_8c14f_104 = combination_tmp_8c14f_84;
    let poseidon_partial_round_output_tmp_8c14f_105 = [
        cube_252_output_tmp_8c14f_71,
        linear_combination_n_1_coefs_2_output_tmp_8c14f_104,
    ];
    let enabler_col168 = eval.enabler();
    eval.set_col(168, enabler_col168);
    eval.set_lookup_word(167, m31_1343313504);
    eval.set_lookup_word(168, input_limb_0_col0);
    eval.set_lookup_word(169, input_limb_1_col1);
    eval.set_lookup_word(170, input_limb_2_col2);
    eval.set_lookup_word(171, input_limb_3_col3);
    eval.set_lookup_word(172, input_limb_4_col4);
    eval.set_lookup_word(173, input_limb_5_col5);
    eval.set_lookup_word(174, input_limb_6_col6);
    eval.set_lookup_word(175, input_limb_7_col7);
    eval.set_lookup_word(176, input_limb_8_col8);
    eval.set_lookup_word(177, input_limb_9_col9);
    eval.set_lookup_word(178, input_limb_10_col10);
    eval.set_lookup_word(179, input_limb_11_col11);
    eval.set_lookup_word(180, input_limb_12_col12);
    eval.set_lookup_word(181, input_limb_13_col13);
    eval.set_lookup_word(182, input_limb_14_col14);
    eval.set_lookup_word(183, input_limb_15_col15);
    eval.set_lookup_word(184, input_limb_16_col16);
    eval.set_lookup_word(185, input_limb_17_col17);
    eval.set_lookup_word(186, input_limb_18_col18);
    eval.set_lookup_word(187, input_limb_19_col19);
    eval.set_lookup_word(188, input_limb_20_col20);
    eval.set_lookup_word(189, input_limb_21_col21);
    eval.set_lookup_word(190, input_limb_22_col22);
    eval.set_lookup_word(191, input_limb_23_col23);
    eval.set_lookup_word(192, input_limb_24_col24);
    eval.set_lookup_word(193, input_limb_25_col25);
    eval.set_lookup_word(194, input_limb_26_col26);
    eval.set_lookup_word(195, input_limb_27_col27);
    eval.set_lookup_word(196, input_limb_28_col28);
    eval.set_lookup_word(197, input_limb_29_col29);
    eval.set_lookup_word(198, input_limb_30_col30);
    eval.set_lookup_word(199, input_limb_31_col31);
    eval.set_lookup_word(200, input_limb_32_col32);
    eval.set_lookup_word(201, input_limb_33_col33);
    eval.set_lookup_word(202, input_limb_34_col34);
    eval.set_lookup_word(203, input_limb_35_col35);
    eval.set_lookup_word(204, input_limb_36_col36);
    eval.set_lookup_word(205, input_limb_37_col37);
    eval.set_lookup_word(206, input_limb_38_col38);
    eval.set_lookup_word(207, input_limb_39_col39);
    eval.set_lookup_word(208, input_limb_40_col40);
    eval.set_lookup_word(209, input_limb_41_col41);
    eval.set_lookup_word(210, m31_1343313504);
    eval.set_lookup_word(211, input_limb_0_col0);
    let wg_v1569 = eval.m31_add(input_limb_1_col1, m31_1);
    eval.set_lookup_word(212, wg_v1569);
    eval.set_lookup_word(213, cube_252_output_limb_0_col104);
    eval.set_lookup_word(214, cube_252_output_limb_1_col105);
    eval.set_lookup_word(215, cube_252_output_limb_2_col106);
    eval.set_lookup_word(216, cube_252_output_limb_3_col107);
    eval.set_lookup_word(217, cube_252_output_limb_4_col108);
    eval.set_lookup_word(218, cube_252_output_limb_5_col109);
    eval.set_lookup_word(219, cube_252_output_limb_6_col110);
    eval.set_lookup_word(220, cube_252_output_limb_7_col111);
    eval.set_lookup_word(221, cube_252_output_limb_8_col112);
    eval.set_lookup_word(222, cube_252_output_limb_9_col113);
    eval.set_lookup_word(223, combination_limb_0_col125);
    eval.set_lookup_word(224, combination_limb_1_col126);
    eval.set_lookup_word(225, combination_limb_2_col127);
    eval.set_lookup_word(226, combination_limb_3_col128);
    eval.set_lookup_word(227, combination_limb_4_col129);
    eval.set_lookup_word(228, combination_limb_5_col130);
    eval.set_lookup_word(229, combination_limb_6_col131);
    eval.set_lookup_word(230, combination_limb_7_col132);
    eval.set_lookup_word(231, combination_limb_8_col133);
    eval.set_lookup_word(232, combination_limb_9_col134);
    eval.set_lookup_word(233, cube_252_output_limb_0_col136);
    eval.set_lookup_word(234, cube_252_output_limb_1_col137);
    eval.set_lookup_word(235, cube_252_output_limb_2_col138);
    eval.set_lookup_word(236, cube_252_output_limb_3_col139);
    eval.set_lookup_word(237, cube_252_output_limb_4_col140);
    eval.set_lookup_word(238, cube_252_output_limb_5_col141);
    eval.set_lookup_word(239, cube_252_output_limb_6_col142);
    eval.set_lookup_word(240, cube_252_output_limb_7_col143);
    eval.set_lookup_word(241, cube_252_output_limb_8_col144);
    eval.set_lookup_word(242, cube_252_output_limb_9_col145);
    eval.set_lookup_word(243, combination_limb_0_col157);
    eval.set_lookup_word(244, combination_limb_1_col158);
    eval.set_lookup_word(245, combination_limb_2_col159);
    eval.set_lookup_word(246, combination_limb_3_col160);
    eval.set_lookup_word(247, combination_limb_4_col161);
    eval.set_lookup_word(248, combination_limb_5_col162);
    eval.set_lookup_word(249, combination_limb_6_col163);
    eval.set_lookup_word(250, combination_limb_7_col164);
    eval.set_lookup_word(251, combination_limb_8_col165);
    eval.set_lookup_word(252, combination_limb_9_col166);
    eval.set_lookup_word(253, m31_1);
    eval.set_lookup_word(254, enabler_col168);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `poseidon_3_partial_rounds_chain_row_body` on a per-row `SimdWitnessEval`, then reconstructs the
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
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
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
    let Felt252_4_0_0_0 = PackedFelt252::broadcast(Felt252::from([4, 0, 0, 0]));
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
                (row, lookup_data, sub_component_inputs, poseidon_3_partial_rounds_chain_input),
            )| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    None,
                    vec![
                        poseidon_3_partial_rounds_chain_input.0.into_simd(),
                        poseidon_3_partial_rounds_chain_input.1.into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(0)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(1)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(2)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(3)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(4)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(5)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(6)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(7)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(8)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[0]
                            .get_m31(9)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(0)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(1)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(2)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(3)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(4)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(5)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(6)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(7)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(8)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[1]
                            .get_m31(9)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(0)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(1)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(2)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(3)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(4)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(5)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(6)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(7)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(8)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[2]
                            .get_m31(9)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(0)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(1)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(2)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(3)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(4)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(5)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(6)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(7)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(8)
                            .into_simd(),
                        poseidon_3_partial_rounds_chain_input.2[3]
                            .get_m31(9)
                            .into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                poseidon_3_partial_rounds_chain_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.poseidon_round_keys_0 = [
                    lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10],
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30],
                    lw[31],
                ];
                *lookup_data.cube_252_1 = [
                    lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40], lw[41],
                    lw[42], lw[43], lw[44], lw[45], lw[46], lw[47], lw[48], lw[49], lw[50], lw[51],
                    lw[52],
                ];
                *lookup_data.range_check_4_4_4_4_2 = [lw[53], lw[54], lw[55], lw[56], lw[57]];
                *lookup_data.range_check_4_4_4_4_3 = [lw[58], lw[59], lw[60], lw[61], lw[62]];
                *lookup_data.range_check_4_4_4 = [lw[63], lw[64], lw[65]];
                *lookup_data.range_check_252_width_27_5 = [
                    lw[66], lw[67], lw[68], lw[69], lw[70], lw[71], lw[72], lw[73], lw[74], lw[75],
                    lw[76],
                ];
                *lookup_data.cube_252_6 = [
                    lw[77], lw[78], lw[79], lw[80], lw[81], lw[82], lw[83], lw[84], lw[85], lw[86],
                    lw[87], lw[88], lw[89], lw[90], lw[91], lw[92], lw[93], lw[94], lw[95], lw[96],
                    lw[97],
                ];
                *lookup_data.range_check_4_4_4_4_7 = [lw[98], lw[99], lw[100], lw[101], lw[102]];
                *lookup_data.range_check_4_4_4_4_8 = [lw[103], lw[104], lw[105], lw[106], lw[107]];
                *lookup_data.range_check_4_4_9 = [lw[108], lw[109], lw[110]];
                *lookup_data.range_check_252_width_27_10 = [
                    lw[111], lw[112], lw[113], lw[114], lw[115], lw[116], lw[117], lw[118],
                    lw[119], lw[120], lw[121],
                ];
                *lookup_data.cube_252_11 = [
                    lw[122], lw[123], lw[124], lw[125], lw[126], lw[127], lw[128], lw[129],
                    lw[130], lw[131], lw[132], lw[133], lw[134], lw[135], lw[136], lw[137],
                    lw[138], lw[139], lw[140], lw[141], lw[142],
                ];
                *lookup_data.range_check_4_4_4_4_12 = [lw[143], lw[144], lw[145], lw[146], lw[147]];
                *lookup_data.range_check_4_4_4_4_13 = [lw[148], lw[149], lw[150], lw[151], lw[152]];
                *lookup_data.range_check_4_4_14 = [lw[153], lw[154], lw[155]];
                *lookup_data.range_check_252_width_27_15 = [
                    lw[156], lw[157], lw[158], lw[159], lw[160], lw[161], lw[162], lw[163],
                    lw[164], lw[165], lw[166],
                ];
                *lookup_data.poseidon_3_partial_rounds_chain_16 = [
                    lw[167], lw[168], lw[169], lw[170], lw[171], lw[172], lw[173], lw[174],
                    lw[175], lw[176], lw[177], lw[178], lw[179], lw[180], lw[181], lw[182],
                    lw[183], lw[184], lw[185], lw[186], lw[187], lw[188], lw[189], lw[190],
                    lw[191], lw[192], lw[193], lw[194], lw[195], lw[196], lw[197], lw[198],
                    lw[199], lw[200], lw[201], lw[202], lw[203], lw[204], lw[205], lw[206],
                    lw[207], lw[208], lw[209],
                ];
                *lookup_data.poseidon_3_partial_rounds_chain_17 = [
                    lw[210], lw[211], lw[212], lw[213], lw[214], lw[215], lw[216], lw[217],
                    lw[218], lw[219], lw[220], lw[221], lw[222], lw[223], lw[224], lw[225],
                    lw[226], lw[227], lw[228], lw[229], lw[230], lw[231], lw[232], lw[233],
                    lw[234], lw[235], lw[236], lw[237], lw[238], lw[239], lw[240], lw[241],
                    lw[242], lw[243], lw[244], lw[245], lw[246], lw[247], lw[248], lw[249],
                    lw[250], lw[251], lw[252],
                ];
                *lookup_data.mults_0 = lw[253];
                *lookup_data.mults_1 = lw[254];
                let sw = eval.sub_scratch();
                *sub_component_inputs.poseidon_round_keys[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[0]) }];
                *sub_component_inputs.cube_252[0] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[3]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[4]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                ]);
                *sub_component_inputs.cube_252[1] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[15]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[18]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                ]);
                *sub_component_inputs.cube_252[2] = PackedFelt252Width27::from_limbs([
                    unsafe { PackedM31::from_simd_unchecked(sw[21]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[23]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[24]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[25]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[26]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[27]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[28]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[29]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[30]) },
                ]);
                *sub_component_inputs.range_check_4_4_4_4[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[31]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[32]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[33]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[34]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[35]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[36]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[37]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[38]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[39]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[40]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[41]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[42]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[43]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[44]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[45]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[46]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[4] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[47]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[48]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[49]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[50]) },
                ];
                *sub_component_inputs.range_check_4_4_4_4[5] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[51]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[52]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[53]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[54]) },
                ];
                *sub_component_inputs.range_check_4_4[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[55]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[56])
                    }];
                *sub_component_inputs.range_check_4_4[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[57]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[58])
                    }];
                *sub_component_inputs.range_check_4_4[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[59]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[60])
                    }];
                *sub_component_inputs.range_check_252_width_27[0] =
                    PackedFelt252Width27::from_limbs([
                        unsafe { PackedM31::from_simd_unchecked(sw[61]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[62]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[63]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[64]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[65]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[66]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[67]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[68]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[69]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[70]) },
                    ]);
                *sub_component_inputs.range_check_252_width_27[1] =
                    PackedFelt252Width27::from_limbs([
                        unsafe { PackedM31::from_simd_unchecked(sw[71]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[72]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[73]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[74]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[75]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[76]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[77]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[78]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[79]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[80]) },
                    ]);
                *sub_component_inputs.range_check_252_width_27[2] =
                    PackedFelt252Width27::from_limbs([
                        unsafe { PackedM31::from_simd_unchecked(sw[81]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[82]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[83]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[84]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[85]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[86]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[87]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[88]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[89]) },
                        unsafe { PackedM31::from_simd_unchecked(sw[90]) },
                    ]);
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
        poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
        cube_252_state: &cube_252::ClaimGenerator,
        range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
        range_check_4_4_state: &range_check_4_4::ClaimGenerator,
        range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
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
            poseidon_round_keys_state,
            cube_252_state,
            range_check_4_4_4_4_state,
            range_check_4_4_state,
            range_check_252_width_27_state,
        );
        for inputs in sub_component_inputs.poseidon_round_keys {
            add_inputs(
                poseidon_round_keys_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.cube_252 {
            add_inputs(cube_252_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_4_4_4_4 {
            add_inputs(
                range_check_4_4_4_4_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.range_check_4_4 {
            add_inputs(range_check_4_4_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_252_width_27 {
            add_inputs(
                range_check_252_width_27_state,
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

/// Record the `poseidon_3_partial_rounds_chain` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_poseidon_3_partial_rounds_chain() -> RecordingOutput {
    let mut eval =
        RecordingWitnessEval::with_slots("poseidon_3_partial_rounds_chain", 42, Some(43));
    poseidon_3_partial_rounds_chain_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    255;
    poseidon_round_keys_0: 32,
    cube_252_1: 21,
    range_check_4_4_4_4_2: 5,
    range_check_4_4_4_4_3: 5,
    range_check_4_4_4: 3,
    range_check_252_width_27_5: 11,
    cube_252_6: 21,
    range_check_4_4_4_4_7: 5,
    range_check_4_4_4_4_8: 5,
    range_check_4_4_9: 3,
    range_check_252_width_27_10: 11,
    cube_252_11: 21,
    range_check_4_4_4_4_12: 5,
    range_check_4_4_4_4_13: 5,
    range_check_4_4_14: 3,
    range_check_252_width_27_15: 11,
    poseidon_3_partial_rounds_chain_16: 43,
    poseidon_3_partial_rounds_chain_17: 43,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    (
        "poseidon_round_keys",
        0,
        "poseidon_round_keys_state",
        0,
        0,
        1,
    ),
    ("cube_252", 0, "cube_252_state", 0, 1, 10),
    ("cube_252", 1, "cube_252_state", 0, 11, 10),
    ("cube_252", 2, "cube_252_state", 0, 21, 10),
    (
        "range_check_4_4_4_4",
        0,
        "range_check_4_4_4_4_state",
        0,
        31,
        4,
    ),
    (
        "range_check_4_4_4_4",
        1,
        "range_check_4_4_4_4_state",
        0,
        35,
        4,
    ),
    (
        "range_check_4_4_4_4",
        2,
        "range_check_4_4_4_4_state",
        0,
        39,
        4,
    ),
    (
        "range_check_4_4_4_4",
        3,
        "range_check_4_4_4_4_state",
        0,
        43,
        4,
    ),
    (
        "range_check_4_4_4_4",
        4,
        "range_check_4_4_4_4_state",
        0,
        47,
        4,
    ),
    (
        "range_check_4_4_4_4",
        5,
        "range_check_4_4_4_4_state",
        0,
        51,
        4,
    ),
    ("range_check_4_4", 0, "range_check_4_4_state", 0, 55, 2),
    ("range_check_4_4", 1, "range_check_4_4_state", 0, 57, 2),
    ("range_check_4_4", 2, "range_check_4_4_state", 0, 59, 2),
    (
        "range_check_252_width_27",
        0,
        "range_check_252_width_27_state",
        0,
        61,
        10,
    ),
    (
        "range_check_252_width_27",
        1,
        "range_check_252_width_27_state",
        0,
        71,
        10,
    ),
    (
        "range_check_252_width_27",
        2,
        "range_check_252_width_27_state",
        0,
        81,
        10,
    ),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "poseidon_round_keys_0",
        "mults_0",
        false,
        "cube_252_1",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_2",
        "mults_0",
        false,
        "range_check_4_4_4_4_3",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4",
        "mults_0",
        false,
        "range_check_252_width_27_5",
        "mults_0",
        false,
    ),
    (
        "cube_252_6",
        "mults_0",
        false,
        "range_check_4_4_4_4_7",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_8",
        "mults_0",
        false,
        "range_check_4_4_9",
        "mults_0",
        false,
    ),
    (
        "range_check_252_width_27_10",
        "mults_0",
        false,
        "cube_252_11",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_4_4_12",
        "mults_0",
        false,
        "range_check_4_4_4_4_13",
        "mults_0",
        false,
    ),
    (
        "range_check_4_4_14",
        "mults_0",
        false,
        "range_check_252_width_27_15",
        "mults_0",
        false,
    ),
    (
        "poseidon_3_partial_rounds_chain_16",
        "mults_1",
        false,
        "poseidon_3_partial_rounds_chain_17",
        "mults_1",
        true,
    ),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.poseidon_round_keys_0.iter().flatten().copied().collect(),
        ld.cube_252_1.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_2.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_3.iter().flatten().copied().collect(),
        ld.range_check_4_4_4.iter().flatten().copied().collect(),
        ld.range_check_252_width_27_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.cube_252_6.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_7.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_8.iter().flatten().copied().collect(),
        ld.range_check_4_4_9.iter().flatten().copied().collect(),
        ld.range_check_252_width_27_10
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.cube_252_11.iter().flatten().copied().collect(),
        ld.range_check_4_4_4_4_12
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_4_4_13
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.range_check_4_4_14.iter().flatten().copied().collect(),
        ld.range_check_252_width_27_15
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_3_partial_rounds_chain_16
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_3_partial_rounds_chain_17
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
        sci.poseidon_round_keys[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
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
        sci.range_check_4_4_4_4[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[1]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[2]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[3]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[4]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4_4_4[5]
            .iter()
            .flat_map(|t| {
                vec![
                    t[0].into_simd(),
                    t[1].into_simd(),
                    t[2].into_simd(),
                    t[3].into_simd(),
                ]
            })
            .collect::<Vec<_>>(),
        sci.range_check_4_4[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_4_4[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_4_4[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_252_width_27[0]
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
        sci.range_check_252_width_27[1]
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
        sci.range_check_252_width_27[2]
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
    poseidon_round_keys_state: &poseidon_round_keys::ClaimGenerator,
    cube_252_state: &cube_252::ClaimGenerator,
    range_check_4_4_4_4_state: &range_check_4_4_4_4::ClaimGenerator,
    range_check_4_4_state: &range_check_4_4::ClaimGenerator,
    range_check_252_width_27_state: &range_check_252_width_27::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        poseidon_round_keys_state,
        cube_252_state,
        range_check_4_4_4_4_state,
        range_check_4_4_state,
        range_check_252_width_27_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        n_rows,
        poseidon_round_keys_state,
        cube_252_state,
        range_check_4_4_4_4_state,
        range_check_4_4_state,
        range_check_252_width_27_state,
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
    poseidon_round_keys_0: Vec<[PackedM31; 32]>,
    cube_252_1: Vec<[PackedM31; 21]>,
    range_check_4_4_4_4_2: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_3: Vec<[PackedM31; 5]>,
    range_check_4_4_4: Vec<[PackedM31; 3]>,
    range_check_252_width_27_5: Vec<[PackedM31; 11]>,
    cube_252_6: Vec<[PackedM31; 21]>,
    range_check_4_4_4_4_7: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_8: Vec<[PackedM31; 5]>,
    range_check_4_4_9: Vec<[PackedM31; 3]>,
    range_check_252_width_27_10: Vec<[PackedM31; 11]>,
    cube_252_11: Vec<[PackedM31; 21]>,
    range_check_4_4_4_4_12: Vec<[PackedM31; 5]>,
    range_check_4_4_4_4_13: Vec<[PackedM31; 5]>,
    range_check_4_4_14: Vec<[PackedM31; 3]>,
    range_check_252_width_27_15: Vec<[PackedM31; 11]>,
    poseidon_3_partial_rounds_chain_16: Vec<[PackedM31; 43]>,
    poseidon_3_partial_rounds_chain_17: Vec<[PackedM31; 43]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    poseidon_round_keys_0: 32,
    cube_252_1: 21,
    range_check_4_4_4_4_2: 5,
    range_check_4_4_4_4_3: 5,
    range_check_4_4_4: 3,
    range_check_252_width_27_5: 11,
    cube_252_6: 21,
    range_check_4_4_4_4_7: 5,
    range_check_4_4_4_4_8: 5,
    range_check_4_4_9: 3,
    range_check_252_width_27_10: 11,
    cube_252_11: 21,
    range_check_4_4_4_4_12: 5,
    range_check_4_4_4_4_13: 5,
    range_check_4_4_14: 3,
    range_check_252_width_27_15: 11,
    poseidon_3_partial_rounds_chain_16: 43,
    poseidon_3_partial_rounds_chain_17: 43,
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
            &self.lookup_data.poseidon_round_keys_0,
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
            &self.lookup_data.range_check_4_4_4_4_2,
            &self.lookup_data.range_check_4_4_4_4_3,
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
            &self.lookup_data.range_check_4_4_4,
            &self.lookup_data.range_check_252_width_27_5,
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
            &self.lookup_data.cube_252_6,
            &self.lookup_data.range_check_4_4_4_4_7,
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
            &self.lookup_data.range_check_4_4_4_4_8,
            &self.lookup_data.range_check_4_4_9,
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
            &self.lookup_data.range_check_252_width_27_10,
            &self.lookup_data.cube_252_11,
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
            &self.lookup_data.range_check_4_4_4_4_12,
            &self.lookup_data.range_check_4_4_4_4_13,
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
            &self.lookup_data.range_check_4_4_14,
            &self.lookup_data.range_check_252_width_27_15,
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
            &self.lookup_data.poseidon_3_partial_rounds_chain_16,
            &self.lookup_data.poseidon_3_partial_rounds_chain_17,
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
