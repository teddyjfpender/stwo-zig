// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::range_check_252_width_27::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{range_check_18, range_check_9_9};
use crate::witness::prelude::*;

pub type InputType = Felt252Width27;
pub type PackedInputType = PackedFelt252Width27;

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
        range_check_9_9_state: &range_check_9_9::ClaimGenerator,
        range_check_18_state: &range_check_18::ClaimGenerator,
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
            range_check_9_9_state,
            range_check_18_state,
        );
        for inputs in sub_component_inputs.range_check_9_9 {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_18 {
            add_inputs(range_check_18_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_9_9_b {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_18_b {
            add_inputs(range_check_18_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_9_9_c {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 2);
        }
        for inputs in sub_component_inputs.range_check_9_9_d {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 3);
        }
        for inputs in sub_component_inputs.range_check_9_9_e {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 4);
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
    range_check_9_9: [Vec<range_check_9_9::PackedInputType>; 1],
    range_check_18: [Vec<range_check_18::PackedInputType>; 7],
    range_check_9_9_b: [Vec<range_check_9_9::PackedInputType>; 1],
    range_check_18_b: [Vec<range_check_18::PackedInputType>; 2],
    range_check_9_9_c: [Vec<range_check_9_9::PackedInputType>; 1],
    range_check_9_9_d: [Vec<range_check_9_9::PackedInputType>; 1],
    range_check_9_9_e: [Vec<range_check_9_9::PackedInputType>; 1],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_18_state: &range_check_18::ClaimGenerator,
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

    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1090315331 = PackedM31::broadcast(M31::from(1090315331));
    let M31_1109051422 = PackedM31::broadcast(M31::from(1109051422));
    let M31_1424798916 = PackedM31::broadcast(M31::from(1424798916));
    let M31_1847459238 = PackedM31::broadcast(M31::from(1847459238));
    let M31_1864236857 = PackedM31::broadcast(M31::from(1864236857));
    let M31_1881014476 = PackedM31::broadcast(M31::from(1881014476));
    let M31_1897792095 = PackedM31::broadcast(M31::from(1897792095));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_4194304 = PackedM31::broadcast(M31::from(4194304));
    let M31_517791011 = PackedM31::broadcast(M31::from(517791011));
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
                (row, lookup_data, sub_component_inputs, range_check_252_width_27_input),
            )| {
                let input_limb_0_col0 = range_check_252_width_27_input.get_m31(0);
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = range_check_252_width_27_input.get_m31(1);
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = range_check_252_width_27_input.get_m31(2);
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = range_check_252_width_27_input.get_m31(3);
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = range_check_252_width_27_input.get_m31(4);
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = range_check_252_width_27_input.get_m31(5);
                *row[5] = input_limb_5_col5;
                let input_limb_6_col6 = range_check_252_width_27_input.get_m31(6);
                *row[6] = input_limb_6_col6;
                let input_limb_7_col7 = range_check_252_width_27_input.get_m31(7);
                *row[7] = input_limb_7_col7;
                let input_limb_8_col8 = range_check_252_width_27_input.get_m31(8);
                *row[8] = input_limb_8_col8;
                let input_limb_9_col9 = range_check_252_width_27_input.get_m31(9);
                *row[9] = input_limb_9_col9;
                let input_as_felt252_tmp_6d30a_0 =
                    PackedFelt252::from_packed_felt252width27(range_check_252_width_27_input);
                let limb_0_high_part_col10 = input_as_felt252_tmp_6d30a_0.get_m31(2);
                *row[10] = limb_0_high_part_col10;
                let limb_1_low_part_col11 = input_as_felt252_tmp_6d30a_0.get_m31(3);
                *row[11] = limb_1_low_part_col11;
                *sub_component_inputs.range_check_9_9[0] =
                    [limb_0_high_part_col10, limb_1_low_part_col11];
                *lookup_data.range_check_9_9_0 =
                    [M31_517791011, limb_0_high_part_col10, limb_1_low_part_col11];
                *sub_component_inputs.range_check_18[0] =
                    [((input_limb_0_col0) - ((limb_0_high_part_col10) * (M31_262144)))];
                *lookup_data.range_check_18_1 = [
                    M31_1109051422,
                    ((input_limb_0_col0) - ((limb_0_high_part_col10) * (M31_262144))),
                ];
                *sub_component_inputs.range_check_18[1] =
                    [(((input_limb_1_col1) - (limb_1_low_part_col11)) * (M31_4194304))];
                *lookup_data.range_check_18_2 = [
                    M31_1109051422,
                    (((input_limb_1_col1) - (limb_1_low_part_col11)) * (M31_4194304)),
                ];
                let limb_2_high_part_col12 = input_as_felt252_tmp_6d30a_0.get_m31(8);
                *row[12] = limb_2_high_part_col12;
                let limb_3_low_part_col13 = input_as_felt252_tmp_6d30a_0.get_m31(9);
                *row[13] = limb_3_low_part_col13;
                *sub_component_inputs.range_check_9_9_b[0] =
                    [limb_2_high_part_col12, limb_3_low_part_col13];
                *lookup_data.range_check_9_9_b_3 = [
                    M31_1897792095,
                    limb_2_high_part_col12,
                    limb_3_low_part_col13,
                ];
                *sub_component_inputs.range_check_18_b[0] =
                    [((input_limb_2_col2) - ((limb_2_high_part_col12) * (M31_262144)))];
                *lookup_data.range_check_18_b_4 = [
                    M31_1424798916,
                    ((input_limb_2_col2) - ((limb_2_high_part_col12) * (M31_262144))),
                ];
                *sub_component_inputs.range_check_18[2] =
                    [(((input_limb_3_col3) - (limb_3_low_part_col13)) * (M31_4194304))];
                *lookup_data.range_check_18_5 = [
                    M31_1109051422,
                    (((input_limb_3_col3) - (limb_3_low_part_col13)) * (M31_4194304)),
                ];
                let limb_4_high_part_col14 = input_as_felt252_tmp_6d30a_0.get_m31(14);
                *row[14] = limb_4_high_part_col14;
                let limb_5_low_part_col15 = input_as_felt252_tmp_6d30a_0.get_m31(15);
                *row[15] = limb_5_low_part_col15;
                *sub_component_inputs.range_check_9_9_c[0] =
                    [limb_4_high_part_col14, limb_5_low_part_col15];
                *lookup_data.range_check_9_9_c_6 = [
                    M31_1881014476,
                    limb_4_high_part_col14,
                    limb_5_low_part_col15,
                ];
                *sub_component_inputs.range_check_18[3] =
                    [((input_limb_4_col4) - ((limb_4_high_part_col14) * (M31_262144)))];
                *lookup_data.range_check_18_7 = [
                    M31_1109051422,
                    ((input_limb_4_col4) - ((limb_4_high_part_col14) * (M31_262144))),
                ];
                *sub_component_inputs.range_check_18[4] =
                    [(((input_limb_5_col5) - (limb_5_low_part_col15)) * (M31_4194304))];
                *lookup_data.range_check_18_8 = [
                    M31_1109051422,
                    (((input_limb_5_col5) - (limb_5_low_part_col15)) * (M31_4194304)),
                ];
                let limb_6_high_part_col16 = input_as_felt252_tmp_6d30a_0.get_m31(20);
                *row[16] = limb_6_high_part_col16;
                let limb_7_low_part_col17 = input_as_felt252_tmp_6d30a_0.get_m31(21);
                *row[17] = limb_7_low_part_col17;
                *sub_component_inputs.range_check_9_9_d[0] =
                    [limb_6_high_part_col16, limb_7_low_part_col17];
                *lookup_data.range_check_9_9_d_9 = [
                    M31_1864236857,
                    limb_6_high_part_col16,
                    limb_7_low_part_col17,
                ];
                *sub_component_inputs.range_check_18_b[1] =
                    [((input_limb_6_col6) - ((limb_6_high_part_col16) * (M31_262144)))];
                *lookup_data.range_check_18_b_10 = [
                    M31_1424798916,
                    ((input_limb_6_col6) - ((limb_6_high_part_col16) * (M31_262144))),
                ];
                *sub_component_inputs.range_check_18[5] =
                    [(((input_limb_7_col7) - (limb_7_low_part_col17)) * (M31_4194304))];
                *lookup_data.range_check_18_11 = [
                    M31_1109051422,
                    (((input_limb_7_col7) - (limb_7_low_part_col17)) * (M31_4194304)),
                ];
                let limb_8_high_part_col18 = input_as_felt252_tmp_6d30a_0.get_m31(26);
                *row[18] = limb_8_high_part_col18;
                *sub_component_inputs.range_check_9_9_e[0] =
                    [limb_8_high_part_col18, input_limb_9_col9];
                *lookup_data.range_check_9_9_e_12 =
                    [M31_1847459238, limb_8_high_part_col18, input_limb_9_col9];
                *sub_component_inputs.range_check_18[6] =
                    [((input_limb_8_col8) - ((limb_8_high_part_col18) * (M31_262144)))];
                *lookup_data.range_check_18_13 = [
                    M31_1109051422,
                    ((input_limb_8_col8) - ((limb_8_high_part_col18) * (M31_262144))),
                ];
                let enabler_col19 = enabler_col.packed_at(row_index);
                *row[19] = enabler_col19;
                *lookup_data.range_check_252_width_27_14 = [
                    M31_1090315331,
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
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col19;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `range_check_252_width_27` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     range_check_9_9_0[3] 0..2
//     range_check_18_1[2] 3..4
//     range_check_18_2[2] 5..6
//     range_check_9_9_b_3[3] 7..9
//     range_check_18_b_4[2] 10..11
//     range_check_18_5[2] 12..13
//     range_check_9_9_c_6[3] 14..16
//     range_check_18_7[2] 17..18
//     range_check_18_8[2] 19..20
//     range_check_9_9_d_9[3] 21..23
//     range_check_18_b_10[2] 24..25
//     range_check_18_11[2] 26..27
//     range_check_9_9_e_12[3] 28..30
//     range_check_18_13[2] 31..32
//     range_check_252_width_27_14[11] 33..43
//     mults_0 44
//     mults_1 45
//     (46 words)
//   SUB-INPUT words:
//     range_check_9_9[0] 0..1
//     range_check_18[0] 2
//     range_check_18[1] 3
//     range_check_18[2] 4
//     range_check_18[3] 5
//     range_check_18[4] 6
//     range_check_18[5] 7
//     range_check_18[6] 8
//     range_check_9_9_b[0] 9..10
//     range_check_18_b[0] 11
//     range_check_18_b[1] 12
//     range_check_9_9_c[0] 13..14
//     range_check_9_9_d[0] 15..16
//     range_check_9_9_e[0] 17..18
//     (19 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 46;
pub(crate) const N_SUB_INPUT_WORDS: usize = 19;

/// The per-row `range_check_252_width_27` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn range_check_252_width_27_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_1 = eval.m31_const(1);
    let m31_262144 = eval.m31_const(262144);
    let m31_4194304 = eval.m31_const(4194304);
    let m31_517791011 = eval.m31_const(517791011);
    let m31_1090315331 = eval.m31_const(1090315331);
    let m31_1109051422 = eval.m31_const(1109051422);
    let m31_1424798916 = eval.m31_const(1424798916);
    let m31_1847459238 = eval.m31_const(1847459238);
    let m31_1864236857 = eval.m31_const(1864236857);
    let m31_1881014476 = eval.m31_const(1881014476);
    let m31_1897792095 = eval.m31_const(1897792095);
    let wg_v0 = eval.input(0);
    let wg_v1 = eval.input(1);
    let wg_v2 = eval.input(2);
    let wg_v3 = eval.input(3);
    let wg_v4 = eval.input(4);
    let wg_v5 = eval.input(5);
    let wg_v6 = eval.input(6);
    let wg_v7 = eval.input(7);
    let wg_v8 = eval.input(8);
    let wg_v9 = eval.input(9);
    let wg_v10 = [
        wg_v0, wg_v1, wg_v2, wg_v3, wg_v4, wg_v5, wg_v6, wg_v7, wg_v8, wg_v9,
    ];
    let input_limb_0_col0 = wg_v10[0];
    eval.set_col(0, input_limb_0_col0);
    let wg_v11 = eval.input(0);
    let wg_v12 = eval.input(1);
    let wg_v13 = eval.input(2);
    let wg_v14 = eval.input(3);
    let wg_v15 = eval.input(4);
    let wg_v16 = eval.input(5);
    let wg_v17 = eval.input(6);
    let wg_v18 = eval.input(7);
    let wg_v19 = eval.input(8);
    let wg_v20 = eval.input(9);
    let wg_v21 = [
        wg_v11, wg_v12, wg_v13, wg_v14, wg_v15, wg_v16, wg_v17, wg_v18, wg_v19, wg_v20,
    ];
    let input_limb_1_col1 = wg_v21[1];
    eval.set_col(1, input_limb_1_col1);
    let wg_v22 = eval.input(0);
    let wg_v23 = eval.input(1);
    let wg_v24 = eval.input(2);
    let wg_v25 = eval.input(3);
    let wg_v26 = eval.input(4);
    let wg_v27 = eval.input(5);
    let wg_v28 = eval.input(6);
    let wg_v29 = eval.input(7);
    let wg_v30 = eval.input(8);
    let wg_v31 = eval.input(9);
    let wg_v32 = [
        wg_v22, wg_v23, wg_v24, wg_v25, wg_v26, wg_v27, wg_v28, wg_v29, wg_v30, wg_v31,
    ];
    let input_limb_2_col2 = wg_v32[2];
    eval.set_col(2, input_limb_2_col2);
    let wg_v33 = eval.input(0);
    let wg_v34 = eval.input(1);
    let wg_v35 = eval.input(2);
    let wg_v36 = eval.input(3);
    let wg_v37 = eval.input(4);
    let wg_v38 = eval.input(5);
    let wg_v39 = eval.input(6);
    let wg_v40 = eval.input(7);
    let wg_v41 = eval.input(8);
    let wg_v42 = eval.input(9);
    let wg_v43 = [
        wg_v33, wg_v34, wg_v35, wg_v36, wg_v37, wg_v38, wg_v39, wg_v40, wg_v41, wg_v42,
    ];
    let input_limb_3_col3 = wg_v43[3];
    eval.set_col(3, input_limb_3_col3);
    let wg_v44 = eval.input(0);
    let wg_v45 = eval.input(1);
    let wg_v46 = eval.input(2);
    let wg_v47 = eval.input(3);
    let wg_v48 = eval.input(4);
    let wg_v49 = eval.input(5);
    let wg_v50 = eval.input(6);
    let wg_v51 = eval.input(7);
    let wg_v52 = eval.input(8);
    let wg_v53 = eval.input(9);
    let wg_v54 = [
        wg_v44, wg_v45, wg_v46, wg_v47, wg_v48, wg_v49, wg_v50, wg_v51, wg_v52, wg_v53,
    ];
    let input_limb_4_col4 = wg_v54[4];
    eval.set_col(4, input_limb_4_col4);
    let wg_v55 = eval.input(0);
    let wg_v56 = eval.input(1);
    let wg_v57 = eval.input(2);
    let wg_v58 = eval.input(3);
    let wg_v59 = eval.input(4);
    let wg_v60 = eval.input(5);
    let wg_v61 = eval.input(6);
    let wg_v62 = eval.input(7);
    let wg_v63 = eval.input(8);
    let wg_v64 = eval.input(9);
    let wg_v65 = [
        wg_v55, wg_v56, wg_v57, wg_v58, wg_v59, wg_v60, wg_v61, wg_v62, wg_v63, wg_v64,
    ];
    let input_limb_5_col5 = wg_v65[5];
    eval.set_col(5, input_limb_5_col5);
    let wg_v66 = eval.input(0);
    let wg_v67 = eval.input(1);
    let wg_v68 = eval.input(2);
    let wg_v69 = eval.input(3);
    let wg_v70 = eval.input(4);
    let wg_v71 = eval.input(5);
    let wg_v72 = eval.input(6);
    let wg_v73 = eval.input(7);
    let wg_v74 = eval.input(8);
    let wg_v75 = eval.input(9);
    let wg_v76 = [
        wg_v66, wg_v67, wg_v68, wg_v69, wg_v70, wg_v71, wg_v72, wg_v73, wg_v74, wg_v75,
    ];
    let input_limb_6_col6 = wg_v76[6];
    eval.set_col(6, input_limb_6_col6);
    let wg_v77 = eval.input(0);
    let wg_v78 = eval.input(1);
    let wg_v79 = eval.input(2);
    let wg_v80 = eval.input(3);
    let wg_v81 = eval.input(4);
    let wg_v82 = eval.input(5);
    let wg_v83 = eval.input(6);
    let wg_v84 = eval.input(7);
    let wg_v85 = eval.input(8);
    let wg_v86 = eval.input(9);
    let wg_v87 = [
        wg_v77, wg_v78, wg_v79, wg_v80, wg_v81, wg_v82, wg_v83, wg_v84, wg_v85, wg_v86,
    ];
    let input_limb_7_col7 = wg_v87[7];
    eval.set_col(7, input_limb_7_col7);
    let wg_v88 = eval.input(0);
    let wg_v89 = eval.input(1);
    let wg_v90 = eval.input(2);
    let wg_v91 = eval.input(3);
    let wg_v92 = eval.input(4);
    let wg_v93 = eval.input(5);
    let wg_v94 = eval.input(6);
    let wg_v95 = eval.input(7);
    let wg_v96 = eval.input(8);
    let wg_v97 = eval.input(9);
    let wg_v98 = [
        wg_v88, wg_v89, wg_v90, wg_v91, wg_v92, wg_v93, wg_v94, wg_v95, wg_v96, wg_v97,
    ];
    let input_limb_8_col8 = wg_v98[8];
    eval.set_col(8, input_limb_8_col8);
    let wg_v99 = eval.input(0);
    let wg_v100 = eval.input(1);
    let wg_v101 = eval.input(2);
    let wg_v102 = eval.input(3);
    let wg_v103 = eval.input(4);
    let wg_v104 = eval.input(5);
    let wg_v105 = eval.input(6);
    let wg_v106 = eval.input(7);
    let wg_v107 = eval.input(8);
    let wg_v108 = eval.input(9);
    let wg_v109 = [
        wg_v99, wg_v100, wg_v101, wg_v102, wg_v103, wg_v104, wg_v105, wg_v106, wg_v107, wg_v108,
    ];
    let input_limb_9_col9 = wg_v109[9];
    eval.set_col(9, input_limb_9_col9);
    let wg_v110 = eval.input(0);
    let wg_v111 = eval.input(1);
    let wg_v112 = eval.input(2);
    let wg_v113 = eval.input(3);
    let wg_v114 = eval.input(4);
    let wg_v115 = eval.input(5);
    let wg_v116 = eval.input(6);
    let wg_v117 = eval.input(7);
    let wg_v118 = eval.input(8);
    let wg_v119 = eval.input(9);
    let wg_v120 = [
        wg_v110, wg_v111, wg_v112, wg_v113, wg_v114, wg_v115, wg_v116, wg_v117, wg_v118, wg_v119,
    ];
    let input_as_felt252_tmp_6d30a_0 = eval.felt_from_w27_words(wg_v120);
    let limb_0_high_part_col10 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 2);
    eval.set_col(10, limb_0_high_part_col10);
    let limb_1_low_part_col11 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 3);
    eval.set_col(11, limb_1_low_part_col11);
    eval.set_sub_input_word(0, limb_0_high_part_col10);
    eval.set_sub_input_word(1, limb_1_low_part_col11);
    eval.set_lookup_word(0, m31_517791011);
    eval.set_lookup_word(1, limb_0_high_part_col10);
    eval.set_lookup_word(2, limb_1_low_part_col11);
    let wg_v121 = eval.m31_mul(limb_0_high_part_col10, m31_262144);
    let wg_v122 = eval.m31_sub(input_limb_0_col0, wg_v121);
    eval.set_sub_input_word(2, wg_v122);
    eval.set_lookup_word(3, m31_1109051422);
    let wg_v123 = eval.m31_mul(limb_0_high_part_col10, m31_262144);
    let wg_v124 = eval.m31_sub(input_limb_0_col0, wg_v123);
    eval.set_lookup_word(4, wg_v124);
    let wg_v125 = eval.m31_sub(input_limb_1_col1, limb_1_low_part_col11);
    let wg_v126 = eval.m31_mul(wg_v125, m31_4194304);
    eval.set_sub_input_word(3, wg_v126);
    eval.set_lookup_word(5, m31_1109051422);
    let wg_v127 = eval.m31_sub(input_limb_1_col1, limb_1_low_part_col11);
    let wg_v128 = eval.m31_mul(wg_v127, m31_4194304);
    eval.set_lookup_word(6, wg_v128);
    let limb_2_high_part_col12 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 8);
    eval.set_col(12, limb_2_high_part_col12);
    let limb_3_low_part_col13 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 9);
    eval.set_col(13, limb_3_low_part_col13);
    eval.set_sub_input_word(9, limb_2_high_part_col12);
    eval.set_sub_input_word(10, limb_3_low_part_col13);
    eval.set_lookup_word(7, m31_1897792095);
    eval.set_lookup_word(8, limb_2_high_part_col12);
    eval.set_lookup_word(9, limb_3_low_part_col13);
    let wg_v129 = eval.m31_mul(limb_2_high_part_col12, m31_262144);
    let wg_v130 = eval.m31_sub(input_limb_2_col2, wg_v129);
    eval.set_sub_input_word(11, wg_v130);
    eval.set_lookup_word(10, m31_1424798916);
    let wg_v131 = eval.m31_mul(limb_2_high_part_col12, m31_262144);
    let wg_v132 = eval.m31_sub(input_limb_2_col2, wg_v131);
    eval.set_lookup_word(11, wg_v132);
    let wg_v133 = eval.m31_sub(input_limb_3_col3, limb_3_low_part_col13);
    let wg_v134 = eval.m31_mul(wg_v133, m31_4194304);
    eval.set_sub_input_word(4, wg_v134);
    eval.set_lookup_word(12, m31_1109051422);
    let wg_v135 = eval.m31_sub(input_limb_3_col3, limb_3_low_part_col13);
    let wg_v136 = eval.m31_mul(wg_v135, m31_4194304);
    eval.set_lookup_word(13, wg_v136);
    let limb_4_high_part_col14 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 14);
    eval.set_col(14, limb_4_high_part_col14);
    let limb_5_low_part_col15 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 15);
    eval.set_col(15, limb_5_low_part_col15);
    eval.set_sub_input_word(13, limb_4_high_part_col14);
    eval.set_sub_input_word(14, limb_5_low_part_col15);
    eval.set_lookup_word(14, m31_1881014476);
    eval.set_lookup_word(15, limb_4_high_part_col14);
    eval.set_lookup_word(16, limb_5_low_part_col15);
    let wg_v137 = eval.m31_mul(limb_4_high_part_col14, m31_262144);
    let wg_v138 = eval.m31_sub(input_limb_4_col4, wg_v137);
    eval.set_sub_input_word(5, wg_v138);
    eval.set_lookup_word(17, m31_1109051422);
    let wg_v139 = eval.m31_mul(limb_4_high_part_col14, m31_262144);
    let wg_v140 = eval.m31_sub(input_limb_4_col4, wg_v139);
    eval.set_lookup_word(18, wg_v140);
    let wg_v141 = eval.m31_sub(input_limb_5_col5, limb_5_low_part_col15);
    let wg_v142 = eval.m31_mul(wg_v141, m31_4194304);
    eval.set_sub_input_word(6, wg_v142);
    eval.set_lookup_word(19, m31_1109051422);
    let wg_v143 = eval.m31_sub(input_limb_5_col5, limb_5_low_part_col15);
    let wg_v144 = eval.m31_mul(wg_v143, m31_4194304);
    eval.set_lookup_word(20, wg_v144);
    let limb_6_high_part_col16 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 20);
    eval.set_col(16, limb_6_high_part_col16);
    let limb_7_low_part_col17 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 21);
    eval.set_col(17, limb_7_low_part_col17);
    eval.set_sub_input_word(15, limb_6_high_part_col16);
    eval.set_sub_input_word(16, limb_7_low_part_col17);
    eval.set_lookup_word(21, m31_1864236857);
    eval.set_lookup_word(22, limb_6_high_part_col16);
    eval.set_lookup_word(23, limb_7_low_part_col17);
    let wg_v145 = eval.m31_mul(limb_6_high_part_col16, m31_262144);
    let wg_v146 = eval.m31_sub(input_limb_6_col6, wg_v145);
    eval.set_sub_input_word(12, wg_v146);
    eval.set_lookup_word(24, m31_1424798916);
    let wg_v147 = eval.m31_mul(limb_6_high_part_col16, m31_262144);
    let wg_v148 = eval.m31_sub(input_limb_6_col6, wg_v147);
    eval.set_lookup_word(25, wg_v148);
    let wg_v149 = eval.m31_sub(input_limb_7_col7, limb_7_low_part_col17);
    let wg_v150 = eval.m31_mul(wg_v149, m31_4194304);
    eval.set_sub_input_word(7, wg_v150);
    eval.set_lookup_word(26, m31_1109051422);
    let wg_v151 = eval.m31_sub(input_limb_7_col7, limb_7_low_part_col17);
    let wg_v152 = eval.m31_mul(wg_v151, m31_4194304);
    eval.set_lookup_word(27, wg_v152);
    let limb_8_high_part_col18 = eval.felt_get_m31(&input_as_felt252_tmp_6d30a_0.clone(), 26);
    eval.set_col(18, limb_8_high_part_col18);
    eval.set_sub_input_word(17, limb_8_high_part_col18);
    eval.set_sub_input_word(18, input_limb_9_col9);
    eval.set_lookup_word(28, m31_1847459238);
    eval.set_lookup_word(29, limb_8_high_part_col18);
    eval.set_lookup_word(30, input_limb_9_col9);
    let wg_v153 = eval.m31_mul(limb_8_high_part_col18, m31_262144);
    let wg_v154 = eval.m31_sub(input_limb_8_col8, wg_v153);
    eval.set_sub_input_word(8, wg_v154);
    eval.set_lookup_word(31, m31_1109051422);
    let wg_v155 = eval.m31_mul(limb_8_high_part_col18, m31_262144);
    let wg_v156 = eval.m31_sub(input_limb_8_col8, wg_v155);
    eval.set_lookup_word(32, wg_v156);
    let enabler_col19 = eval.enabler();
    eval.set_col(19, enabler_col19);
    eval.set_lookup_word(33, m31_1090315331);
    eval.set_lookup_word(34, input_limb_0_col0);
    eval.set_lookup_word(35, input_limb_1_col1);
    eval.set_lookup_word(36, input_limb_2_col2);
    eval.set_lookup_word(37, input_limb_3_col3);
    eval.set_lookup_word(38, input_limb_4_col4);
    eval.set_lookup_word(39, input_limb_5_col5);
    eval.set_lookup_word(40, input_limb_6_col6);
    eval.set_lookup_word(41, input_limb_7_col7);
    eval.set_lookup_word(42, input_limb_8_col8);
    eval.set_lookup_word(43, input_limb_9_col9);
    eval.set_lookup_word(44, m31_1);
    eval.set_lookup_word(45, enabler_col19);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `range_check_252_width_27_row_body` on a per-row `SimdWitnessEval`, then reconstructs the
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
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_18_state: &range_check_18::ClaimGenerator,
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
            |(
                row_index,
                (row, lookup_data, sub_component_inputs, range_check_252_width_27_input),
            )| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    None,
                    vec![
                        range_check_252_width_27_input.get_m31(0).into_simd(),
                        range_check_252_width_27_input.get_m31(1).into_simd(),
                        range_check_252_width_27_input.get_m31(2).into_simd(),
                        range_check_252_width_27_input.get_m31(3).into_simd(),
                        range_check_252_width_27_input.get_m31(4).into_simd(),
                        range_check_252_width_27_input.get_m31(5).into_simd(),
                        range_check_252_width_27_input.get_m31(6).into_simd(),
                        range_check_252_width_27_input.get_m31(7).into_simd(),
                        range_check_252_width_27_input.get_m31(8).into_simd(),
                        range_check_252_width_27_input.get_m31(9).into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                range_check_252_width_27_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.range_check_9_9_0 = [lw[0], lw[1], lw[2]];
                *lookup_data.range_check_18_1 = [lw[3], lw[4]];
                *lookup_data.range_check_18_2 = [lw[5], lw[6]];
                *lookup_data.range_check_9_9_b_3 = [lw[7], lw[8], lw[9]];
                *lookup_data.range_check_18_b_4 = [lw[10], lw[11]];
                *lookup_data.range_check_18_5 = [lw[12], lw[13]];
                *lookup_data.range_check_9_9_c_6 = [lw[14], lw[15], lw[16]];
                *lookup_data.range_check_18_7 = [lw[17], lw[18]];
                *lookup_data.range_check_18_8 = [lw[19], lw[20]];
                *lookup_data.range_check_9_9_d_9 = [lw[21], lw[22], lw[23]];
                *lookup_data.range_check_18_b_10 = [lw[24], lw[25]];
                *lookup_data.range_check_18_11 = [lw[26], lw[27]];
                *lookup_data.range_check_9_9_e_12 = [lw[28], lw[29], lw[30]];
                *lookup_data.range_check_18_13 = [lw[31], lw[32]];
                *lookup_data.range_check_252_width_27_14 = [
                    lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40], lw[41], lw[42],
                    lw[43],
                ];
                *lookup_data.mults_0 = lw[44];
                *lookup_data.mults_1 = lw[45];
                let sw = eval.sub_scratch();
                *sub_component_inputs.range_check_9_9[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[0]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[1])
                    }];
                *sub_component_inputs.range_check_18[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[2]) }];
                *sub_component_inputs.range_check_18[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[3]) }];
                *sub_component_inputs.range_check_18[2] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[4]) }];
                *sub_component_inputs.range_check_18[3] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[5]) }];
                *sub_component_inputs.range_check_18[4] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[6]) }];
                *sub_component_inputs.range_check_18[5] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[7]) }];
                *sub_component_inputs.range_check_18[6] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[8]) }];
                *sub_component_inputs.range_check_9_9_b[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[9]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[10])
                    }];
                *sub_component_inputs.range_check_18_b[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[11]) }];
                *sub_component_inputs.range_check_18_b[1] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[12]) }];
                *sub_component_inputs.range_check_9_9_c[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[13]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[14])
                    }];
                *sub_component_inputs.range_check_9_9_d[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[15]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[16])
                    }];
                *sub_component_inputs.range_check_9_9_e[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[17]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[18])
                    }];
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
        range_check_9_9_state: &range_check_9_9::ClaimGenerator,
        range_check_18_state: &range_check_18::ClaimGenerator,
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
            range_check_9_9_state,
            range_check_18_state,
        );
        for inputs in sub_component_inputs.range_check_9_9 {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_18 {
            add_inputs(range_check_18_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_9_9_b {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_18_b {
            add_inputs(range_check_18_state, &inputs, inputs.len() * N_LANES, 1);
        }
        for inputs in sub_component_inputs.range_check_9_9_c {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 2);
        }
        for inputs in sub_component_inputs.range_check_9_9_d {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 3);
        }
        for inputs in sub_component_inputs.range_check_9_9_e {
            add_inputs(range_check_9_9_state, &inputs, inputs.len() * N_LANES, 4);
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

/// Record the `range_check_252_width_27` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_range_check_252_width_27() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("range_check_252_width_27", 10, Some(11));
    range_check_252_width_27_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    46;
    range_check_9_9_0: 3,
    range_check_18_1: 2,
    range_check_18_2: 2,
    range_check_9_9_b_3: 3,
    range_check_18_b_4: 2,
    range_check_18_5: 2,
    range_check_9_9_c_6: 3,
    range_check_18_7: 2,
    range_check_18_8: 2,
    range_check_9_9_d_9: 3,
    range_check_18_b_10: 2,
    range_check_18_11: 2,
    range_check_9_9_e_12: 3,
    range_check_18_13: 2,
    range_check_252_width_27_14: 11,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_9_9", 0, "range_check_9_9_state", 0, 0, 2),
    ("range_check_18", 0, "range_check_18_state", 0, 2, 1),
    ("range_check_18", 1, "range_check_18_state", 0, 3, 1),
    ("range_check_18", 2, "range_check_18_state", 0, 4, 1),
    ("range_check_18", 3, "range_check_18_state", 0, 5, 1),
    ("range_check_18", 4, "range_check_18_state", 0, 6, 1),
    ("range_check_18", 5, "range_check_18_state", 0, 7, 1),
    ("range_check_18", 6, "range_check_18_state", 0, 8, 1),
    ("range_check_9_9_b", 0, "range_check_9_9_state", 1, 9, 2),
    ("range_check_18_b", 0, "range_check_18_state", 1, 11, 1),
    ("range_check_18_b", 1, "range_check_18_state", 1, 12, 1),
    ("range_check_9_9_c", 0, "range_check_9_9_state", 2, 13, 2),
    ("range_check_9_9_d", 0, "range_check_9_9_state", 3, 15, 2),
    ("range_check_9_9_e", 0, "range_check_9_9_state", 4, 17, 2),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "range_check_9_9_0",
        "mults_0",
        false,
        "range_check_18_1",
        "mults_0",
        false,
    ),
    (
        "range_check_18_2",
        "mults_0",
        false,
        "range_check_9_9_b_3",
        "mults_0",
        false,
    ),
    (
        "range_check_18_b_4",
        "mults_0",
        false,
        "range_check_18_5",
        "mults_0",
        false,
    ),
    (
        "range_check_9_9_c_6",
        "mults_0",
        false,
        "range_check_18_7",
        "mults_0",
        false,
    ),
    (
        "range_check_18_8",
        "mults_0",
        false,
        "range_check_9_9_d_9",
        "mults_0",
        false,
    ),
    (
        "range_check_18_b_10",
        "mults_0",
        false,
        "range_check_18_11",
        "mults_0",
        false,
    ),
    (
        "range_check_9_9_e_12",
        "mults_0",
        false,
        "range_check_18_13",
        "mults_0",
        false,
    ),
    (
        "range_check_252_width_27_14",
        "mults_1",
        true,
        "",
        "",
        false,
    ),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.range_check_9_9_0.iter().flatten().copied().collect(),
        ld.range_check_18_1.iter().flatten().copied().collect(),
        ld.range_check_18_2.iter().flatten().copied().collect(),
        ld.range_check_9_9_b_3.iter().flatten().copied().collect(),
        ld.range_check_18_b_4.iter().flatten().copied().collect(),
        ld.range_check_18_5.iter().flatten().copied().collect(),
        ld.range_check_9_9_c_6.iter().flatten().copied().collect(),
        ld.range_check_18_7.iter().flatten().copied().collect(),
        ld.range_check_18_8.iter().flatten().copied().collect(),
        ld.range_check_9_9_d_9.iter().flatten().copied().collect(),
        ld.range_check_18_b_10.iter().flatten().copied().collect(),
        ld.range_check_18_11.iter().flatten().copied().collect(),
        ld.range_check_9_9_e_12.iter().flatten().copied().collect(),
        ld.range_check_18_13.iter().flatten().copied().collect(),
        ld.range_check_252_width_27_14
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
        sci.range_check_9_9[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[3]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[4]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[5]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18[6]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_18_b[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_c[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_d[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_9_9_e[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
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
    range_check_9_9_state: &range_check_9_9::ClaimGenerator,
    range_check_18_state: &range_check_18::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        n_rows.clone(),
        range_check_9_9_state,
        range_check_18_state,
    );
    let (trace_g, ld_g, sci_g) =
        write_trace_generic_simd(inputs, n_rows, range_check_9_9_state, range_check_18_state);
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
    range_check_9_9_0: Vec<[PackedM31; 3]>,
    range_check_18_1: Vec<[PackedM31; 2]>,
    range_check_18_2: Vec<[PackedM31; 2]>,
    range_check_9_9_b_3: Vec<[PackedM31; 3]>,
    range_check_18_b_4: Vec<[PackedM31; 2]>,
    range_check_18_5: Vec<[PackedM31; 2]>,
    range_check_9_9_c_6: Vec<[PackedM31; 3]>,
    range_check_18_7: Vec<[PackedM31; 2]>,
    range_check_18_8: Vec<[PackedM31; 2]>,
    range_check_9_9_d_9: Vec<[PackedM31; 3]>,
    range_check_18_b_10: Vec<[PackedM31; 2]>,
    range_check_18_11: Vec<[PackedM31; 2]>,
    range_check_9_9_e_12: Vec<[PackedM31; 3]>,
    range_check_18_13: Vec<[PackedM31; 2]>,
    range_check_252_width_27_14: Vec<[PackedM31; 11]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    range_check_9_9_0: 3,
    range_check_18_1: 2,
    range_check_18_2: 2,
    range_check_9_9_b_3: 3,
    range_check_18_b_4: 2,
    range_check_18_5: 2,
    range_check_9_9_c_6: 3,
    range_check_18_7: 2,
    range_check_18_8: 2,
    range_check_9_9_d_9: 3,
    range_check_18_b_10: 2,
    range_check_18_11: 2,
    range_check_9_9_e_12: 3,
    range_check_18_13: 2,
    range_check_252_width_27_14: 11,
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
            &self.lookup_data.range_check_9_9_0,
            &self.lookup_data.range_check_18_1,
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
            &self.lookup_data.range_check_18_2,
            &self.lookup_data.range_check_9_9_b_3,
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
            &self.lookup_data.range_check_18_b_4,
            &self.lookup_data.range_check_18_5,
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
            &self.lookup_data.range_check_9_9_c_6,
            &self.lookup_data.range_check_18_7,
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
            &self.lookup_data.range_check_18_8,
            &self.lookup_data.range_check_9_9_d_9,
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
            &self.lookup_data.range_check_18_b_10,
            &self.lookup_data.range_check_18_11,
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
            &self.lookup_data.range_check_9_9_e_12,
            &self.lookup_data.range_check_18_13,
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

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.range_check_252_width_27_14,
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
