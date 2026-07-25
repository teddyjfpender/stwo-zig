// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::triple_xor_32::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::verify_bitwise_xor_8;
use crate::witness::prelude::*;

pub type InputType = [UInt32; 3];
pub type PackedInputType = [PackedUInt32; 3];

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
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
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

        let (trace, lookup_data, sub_component_inputs) =
            write_trace_simd(packed_inputs, n_rows, verify_bitwise_xor_8_state);
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8_b {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                1,
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
    verify_bitwise_xor_8: [Vec<verify_bitwise_xor_8::PackedInputType>; 4],
    verify_bitwise_xor_8_b: [Vec<verify_bitwise_xor_8::PackedInputType>; 4],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
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
    let M31_112558620 = PackedM31::broadcast(M31::from(112558620));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_521092554 = PackedM31::broadcast(M31::from(521092554));
    let M31_990559919 = PackedM31::broadcast(M31::from(990559919));
    let UInt16_8 = PackedUInt16::broadcast(UInt16::from(8));
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
            |(row_index, (row, lookup_data, sub_component_inputs, triple_xor_32_input))| {
                let input_limb_0_col0 = triple_xor_32_input[0].low().as_m31();
                *row[0] = input_limb_0_col0;
                let input_limb_1_col1 = triple_xor_32_input[0].high().as_m31();
                *row[1] = input_limb_1_col1;
                let input_limb_2_col2 = triple_xor_32_input[1].low().as_m31();
                *row[2] = input_limb_2_col2;
                let input_limb_3_col3 = triple_xor_32_input[1].high().as_m31();
                *row[3] = input_limb_3_col3;
                let input_limb_4_col4 = triple_xor_32_input[2].low().as_m31();
                *row[4] = input_limb_4_col4;
                let input_limb_5_col5 = triple_xor_32_input[2].high().as_m31();
                *row[5] = input_limb_5_col5;

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_0 = ((triple_xor_32_input[0].low()) >> (UInt16_8));
                let ms_8_bits_col6 = ms_8_bits_tmp_6e2d1_0.as_m31();
                *row[6] = ms_8_bits_col6;
                let split_16_low_part_size_8_output_tmp_6e2d1_1 = [
                    ((input_limb_0_col0) - ((ms_8_bits_col6) * (M31_256))),
                    ms_8_bits_col6,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_2 = ((triple_xor_32_input[0].high()) >> (UInt16_8));
                let ms_8_bits_col7 = ms_8_bits_tmp_6e2d1_2.as_m31();
                *row[7] = ms_8_bits_col7;
                let split_16_low_part_size_8_output_tmp_6e2d1_3 = [
                    ((input_limb_1_col1) - ((ms_8_bits_col7) * (M31_256))),
                    ms_8_bits_col7,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_4 = ((triple_xor_32_input[1].low()) >> (UInt16_8));
                let ms_8_bits_col8 = ms_8_bits_tmp_6e2d1_4.as_m31();
                *row[8] = ms_8_bits_col8;
                let split_16_low_part_size_8_output_tmp_6e2d1_5 = [
                    ((input_limb_2_col2) - ((ms_8_bits_col8) * (M31_256))),
                    ms_8_bits_col8,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_6 = ((triple_xor_32_input[1].high()) >> (UInt16_8));
                let ms_8_bits_col9 = ms_8_bits_tmp_6e2d1_6.as_m31();
                *row[9] = ms_8_bits_col9;
                let split_16_low_part_size_8_output_tmp_6e2d1_7 = [
                    ((input_limb_3_col3) - ((ms_8_bits_col9) * (M31_256))),
                    ms_8_bits_col9,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_8 = ((triple_xor_32_input[2].low()) >> (UInt16_8));
                let ms_8_bits_col10 = ms_8_bits_tmp_6e2d1_8.as_m31();
                *row[10] = ms_8_bits_col10;
                let split_16_low_part_size_8_output_tmp_6e2d1_9 = [
                    ((input_limb_4_col4) - ((ms_8_bits_col10) * (M31_256))),
                    ms_8_bits_col10,
                ];

                // Split 16 Low Part Size 8.

                let ms_8_bits_tmp_6e2d1_10 = ((triple_xor_32_input[2].high()) >> (UInt16_8));
                let ms_8_bits_col11 = ms_8_bits_tmp_6e2d1_10.as_m31();
                *row[11] = ms_8_bits_col11;
                let split_16_low_part_size_8_output_tmp_6e2d1_11 = [
                    ((input_limb_5_col5) - ((ms_8_bits_col11) * (M31_256))),
                    ms_8_bits_col11,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_6e2d1_12 =
                    ((PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_1[0]))
                        ^ (PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_5[0])));
                let xor_col12 = xor_tmp_6e2d1_12.as_m31();
                *row[12] = xor_col12;
                *sub_component_inputs.verify_bitwise_xor_8[0] = [
                    split_16_low_part_size_8_output_tmp_6e2d1_1[0],
                    split_16_low_part_size_8_output_tmp_6e2d1_5[0],
                    xor_col12,
                ];
                *lookup_data.verify_bitwise_xor_8_0 = [
                    M31_112558620,
                    split_16_low_part_size_8_output_tmp_6e2d1_1[0],
                    split_16_low_part_size_8_output_tmp_6e2d1_5[0],
                    xor_col12,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_6e2d1_14 = ((PackedUInt16::from_m31(xor_col12))
                    ^ (PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_9[0])));
                let xor_col13 = xor_tmp_6e2d1_14.as_m31();
                *row[13] = xor_col13;
                *sub_component_inputs.verify_bitwise_xor_8[1] = [
                    xor_col12,
                    split_16_low_part_size_8_output_tmp_6e2d1_9[0],
                    xor_col13,
                ];
                *lookup_data.verify_bitwise_xor_8_1 = [
                    M31_112558620,
                    xor_col12,
                    split_16_low_part_size_8_output_tmp_6e2d1_9[0],
                    xor_col13,
                ];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_6e2d1_16 = ((PackedUInt16::from_m31(ms_8_bits_col6))
                    ^ (PackedUInt16::from_m31(ms_8_bits_col8)));
                let xor_col14 = xor_tmp_6e2d1_16.as_m31();
                *row[14] = xor_col14;
                *sub_component_inputs.verify_bitwise_xor_8[2] =
                    [ms_8_bits_col6, ms_8_bits_col8, xor_col14];
                *lookup_data.verify_bitwise_xor_8_2 =
                    [M31_112558620, ms_8_bits_col6, ms_8_bits_col8, xor_col14];

                // Bitwise Xor Num Bits 8.

                let xor_tmp_6e2d1_18 = ((PackedUInt16::from_m31(xor_col14))
                    ^ (PackedUInt16::from_m31(ms_8_bits_col10)));
                let xor_col15 = xor_tmp_6e2d1_18.as_m31();
                *row[15] = xor_col15;
                *sub_component_inputs.verify_bitwise_xor_8[3] =
                    [xor_col14, ms_8_bits_col10, xor_col15];
                *lookup_data.verify_bitwise_xor_8_3 =
                    [M31_112558620, xor_col14, ms_8_bits_col10, xor_col15];

                // Bitwise Xor Num Bits 8 B.

                let xor_tmp_6e2d1_20 =
                    ((PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_3[0]))
                        ^ (PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_7[0])));
                let xor_col16 = xor_tmp_6e2d1_20.as_m31();
                *row[16] = xor_col16;
                *sub_component_inputs.verify_bitwise_xor_8_b[0] = [
                    split_16_low_part_size_8_output_tmp_6e2d1_3[0],
                    split_16_low_part_size_8_output_tmp_6e2d1_7[0],
                    xor_col16,
                ];
                *lookup_data.verify_bitwise_xor_8_b_4 = [
                    M31_521092554,
                    split_16_low_part_size_8_output_tmp_6e2d1_3[0],
                    split_16_low_part_size_8_output_tmp_6e2d1_7[0],
                    xor_col16,
                ];

                // Bitwise Xor Num Bits 8 B.

                let xor_tmp_6e2d1_22 = ((PackedUInt16::from_m31(xor_col16))
                    ^ (PackedUInt16::from_m31(split_16_low_part_size_8_output_tmp_6e2d1_11[0])));
                let xor_col17 = xor_tmp_6e2d1_22.as_m31();
                *row[17] = xor_col17;
                *sub_component_inputs.verify_bitwise_xor_8_b[1] = [
                    xor_col16,
                    split_16_low_part_size_8_output_tmp_6e2d1_11[0],
                    xor_col17,
                ];
                *lookup_data.verify_bitwise_xor_8_b_5 = [
                    M31_521092554,
                    xor_col16,
                    split_16_low_part_size_8_output_tmp_6e2d1_11[0],
                    xor_col17,
                ];

                // Bitwise Xor Num Bits 8 B.

                let xor_tmp_6e2d1_24 = ((PackedUInt16::from_m31(ms_8_bits_col7))
                    ^ (PackedUInt16::from_m31(ms_8_bits_col9)));
                let xor_col18 = xor_tmp_6e2d1_24.as_m31();
                *row[18] = xor_col18;
                *sub_component_inputs.verify_bitwise_xor_8_b[2] =
                    [ms_8_bits_col7, ms_8_bits_col9, xor_col18];
                *lookup_data.verify_bitwise_xor_8_b_6 =
                    [M31_521092554, ms_8_bits_col7, ms_8_bits_col9, xor_col18];

                // Bitwise Xor Num Bits 8 B.

                let xor_tmp_6e2d1_26 = ((PackedUInt16::from_m31(xor_col18))
                    ^ (PackedUInt16::from_m31(ms_8_bits_col11)));
                let xor_col19 = xor_tmp_6e2d1_26.as_m31();
                *row[19] = xor_col19;
                *sub_component_inputs.verify_bitwise_xor_8_b[3] =
                    [xor_col18, ms_8_bits_col11, xor_col19];
                *lookup_data.verify_bitwise_xor_8_b_7 =
                    [M31_521092554, xor_col18, ms_8_bits_col11, xor_col19];

                let triple_xor32_output_tmp_6e2d1_28 = PackedUInt32::from_limbs([
                    ((xor_col13) + ((xor_col15) * (M31_256))),
                    ((xor_col17) + ((xor_col19) * (M31_256))),
                ]);
                let enabler_col20 = enabler_col.packed_at(row_index);
                *row[20] = enabler_col20;
                *lookup_data.triple_xor_32_8 = [
                    M31_990559919,
                    input_limb_0_col0,
                    input_limb_1_col1,
                    input_limb_2_col2,
                    input_limb_3_col3,
                    input_limb_4_col4,
                    input_limb_5_col5,
                    triple_xor32_output_tmp_6e2d1_28.low().as_m31(),
                    triple_xor32_output_tmp_6e2d1_28.high().as_m31(),
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col20;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `triple_xor_32` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     verify_bitwise_xor_8_0[4] 0..3
//     verify_bitwise_xor_8_1[4] 4..7
//     verify_bitwise_xor_8_2[4] 8..11
//     verify_bitwise_xor_8_3[4] 12..15
//     verify_bitwise_xor_8_b_4[4] 16..19
//     verify_bitwise_xor_8_b_5[4] 20..23
//     verify_bitwise_xor_8_b_6[4] 24..27
//     verify_bitwise_xor_8_b_7[4] 28..31
//     triple_xor_32_8[9] 32..40
//     mults_0 41
//     mults_1 42
//     (43 words)
//   SUB-INPUT words:
//     verify_bitwise_xor_8[0] 0..2
//     verify_bitwise_xor_8[1] 3..5
//     verify_bitwise_xor_8[2] 6..8
//     verify_bitwise_xor_8[3] 9..11
//     verify_bitwise_xor_8_b[0] 12..14
//     verify_bitwise_xor_8_b[1] 15..17
//     verify_bitwise_xor_8_b[2] 18..20
//     verify_bitwise_xor_8_b[3] 21..23
//     (24 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 43;
pub(crate) const N_SUB_INPUT_WORDS: usize = 24;

/// The per-row `triple_xor_32` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn triple_xor_32_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_1 = eval.m31_const(1);
    let m31_256 = eval.m31_const(256);
    let m31_112558620 = eval.m31_const(112558620);
    let m31_521092554 = eval.m31_const(521092554);
    let m31_990559919 = eval.m31_const(990559919);
    let wg_v0 = eval.input_u32(0);
    let wg_v1 = eval.u32_low(wg_v0);
    let input_limb_0_col0 = eval.u16_as_m31(wg_v1);
    eval.set_col(0, input_limb_0_col0);
    let wg_v2 = eval.input_u32(0);
    let wg_v3 = eval.u32_high(wg_v2);
    let input_limb_1_col1 = eval.u16_as_m31(wg_v3);
    eval.set_col(1, input_limb_1_col1);
    let wg_v4 = eval.input_u32(1);
    let wg_v5 = eval.u32_low(wg_v4);
    let input_limb_2_col2 = eval.u16_as_m31(wg_v5);
    eval.set_col(2, input_limb_2_col2);
    let wg_v6 = eval.input_u32(1);
    let wg_v7 = eval.u32_high(wg_v6);
    let input_limb_3_col3 = eval.u16_as_m31(wg_v7);
    eval.set_col(3, input_limb_3_col3);
    let wg_v8 = eval.input_u32(2);
    let wg_v9 = eval.u32_low(wg_v8);
    let input_limb_4_col4 = eval.u16_as_m31(wg_v9);
    eval.set_col(4, input_limb_4_col4);
    let wg_v10 = eval.input_u32(2);
    let wg_v11 = eval.u32_high(wg_v10);
    let input_limb_5_col5 = eval.u16_as_m31(wg_v11);
    eval.set_col(5, input_limb_5_col5);
    let wg_v12 = eval.input_u32(0);
    let wg_v13 = eval.u32_low(wg_v12);
    let ms_8_bits_tmp_6e2d1_0 = eval.u16_shr(wg_v13, 8);
    let ms_8_bits_col6 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_0);
    eval.set_col(6, ms_8_bits_col6);
    let wg_v14 = eval.m31_mul(ms_8_bits_col6, m31_256);
    let wg_v15 = eval.m31_sub(input_limb_0_col0, wg_v14);
    let split_16_low_part_size_8_output_tmp_6e2d1_1 = [wg_v15, ms_8_bits_col6];
    let wg_v16 = eval.input_u32(0);
    let wg_v17 = eval.u32_high(wg_v16);
    let ms_8_bits_tmp_6e2d1_2 = eval.u16_shr(wg_v17, 8);
    let ms_8_bits_col7 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_2);
    eval.set_col(7, ms_8_bits_col7);
    let wg_v18 = eval.m31_mul(ms_8_bits_col7, m31_256);
    let wg_v19 = eval.m31_sub(input_limb_1_col1, wg_v18);
    let split_16_low_part_size_8_output_tmp_6e2d1_3 = [wg_v19, ms_8_bits_col7];
    let wg_v20 = eval.input_u32(1);
    let wg_v21 = eval.u32_low(wg_v20);
    let ms_8_bits_tmp_6e2d1_4 = eval.u16_shr(wg_v21, 8);
    let ms_8_bits_col8 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_4);
    eval.set_col(8, ms_8_bits_col8);
    let wg_v22 = eval.m31_mul(ms_8_bits_col8, m31_256);
    let wg_v23 = eval.m31_sub(input_limb_2_col2, wg_v22);
    let split_16_low_part_size_8_output_tmp_6e2d1_5 = [wg_v23, ms_8_bits_col8];
    let wg_v24 = eval.input_u32(1);
    let wg_v25 = eval.u32_high(wg_v24);
    let ms_8_bits_tmp_6e2d1_6 = eval.u16_shr(wg_v25, 8);
    let ms_8_bits_col9 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_6);
    eval.set_col(9, ms_8_bits_col9);
    let wg_v26 = eval.m31_mul(ms_8_bits_col9, m31_256);
    let wg_v27 = eval.m31_sub(input_limb_3_col3, wg_v26);
    let split_16_low_part_size_8_output_tmp_6e2d1_7 = [wg_v27, ms_8_bits_col9];
    let wg_v28 = eval.input_u32(2);
    let wg_v29 = eval.u32_low(wg_v28);
    let ms_8_bits_tmp_6e2d1_8 = eval.u16_shr(wg_v29, 8);
    let ms_8_bits_col10 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_8);
    eval.set_col(10, ms_8_bits_col10);
    let wg_v30 = eval.m31_mul(ms_8_bits_col10, m31_256);
    let wg_v31 = eval.m31_sub(input_limb_4_col4, wg_v30);
    let split_16_low_part_size_8_output_tmp_6e2d1_9 = [wg_v31, ms_8_bits_col10];
    let wg_v32 = eval.input_u32(2);
    let wg_v33 = eval.u32_high(wg_v32);
    let ms_8_bits_tmp_6e2d1_10 = eval.u16_shr(wg_v33, 8);
    let ms_8_bits_col11 = eval.u16_as_m31(ms_8_bits_tmp_6e2d1_10);
    eval.set_col(11, ms_8_bits_col11);
    let wg_v34 = eval.m31_mul(ms_8_bits_col11, m31_256);
    let wg_v35 = eval.m31_sub(input_limb_5_col5, wg_v34);
    let split_16_low_part_size_8_output_tmp_6e2d1_11 = [wg_v35, ms_8_bits_col11];
    let wg_v36 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_1[0]);
    let wg_v37 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_5[0]);
    let xor_tmp_6e2d1_12 = eval.u16_xor(wg_v36, wg_v37);
    let xor_col12 = eval.u16_as_m31(xor_tmp_6e2d1_12);
    eval.set_col(12, xor_col12);
    eval.set_sub_input_word(0, split_16_low_part_size_8_output_tmp_6e2d1_1[0]);
    eval.set_sub_input_word(1, split_16_low_part_size_8_output_tmp_6e2d1_5[0]);
    eval.set_sub_input_word(2, xor_col12);
    eval.set_lookup_word(0, m31_112558620);
    eval.set_lookup_word(1, split_16_low_part_size_8_output_tmp_6e2d1_1[0]);
    eval.set_lookup_word(2, split_16_low_part_size_8_output_tmp_6e2d1_5[0]);
    eval.set_lookup_word(3, xor_col12);
    let wg_v38 = eval.u16_from_m31(xor_col12);
    let wg_v39 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_9[0]);
    let xor_tmp_6e2d1_14 = eval.u16_xor(wg_v38, wg_v39);
    let xor_col13 = eval.u16_as_m31(xor_tmp_6e2d1_14);
    eval.set_col(13, xor_col13);
    eval.set_sub_input_word(3, xor_col12);
    eval.set_sub_input_word(4, split_16_low_part_size_8_output_tmp_6e2d1_9[0]);
    eval.set_sub_input_word(5, xor_col13);
    eval.set_lookup_word(4, m31_112558620);
    eval.set_lookup_word(5, xor_col12);
    eval.set_lookup_word(6, split_16_low_part_size_8_output_tmp_6e2d1_9[0]);
    eval.set_lookup_word(7, xor_col13);
    let wg_v40 = eval.u16_from_m31(ms_8_bits_col6);
    let wg_v41 = eval.u16_from_m31(ms_8_bits_col8);
    let xor_tmp_6e2d1_16 = eval.u16_xor(wg_v40, wg_v41);
    let xor_col14 = eval.u16_as_m31(xor_tmp_6e2d1_16);
    eval.set_col(14, xor_col14);
    eval.set_sub_input_word(6, ms_8_bits_col6);
    eval.set_sub_input_word(7, ms_8_bits_col8);
    eval.set_sub_input_word(8, xor_col14);
    eval.set_lookup_word(8, m31_112558620);
    eval.set_lookup_word(9, ms_8_bits_col6);
    eval.set_lookup_word(10, ms_8_bits_col8);
    eval.set_lookup_word(11, xor_col14);
    let wg_v42 = eval.u16_from_m31(xor_col14);
    let wg_v43 = eval.u16_from_m31(ms_8_bits_col10);
    let xor_tmp_6e2d1_18 = eval.u16_xor(wg_v42, wg_v43);
    let xor_col15 = eval.u16_as_m31(xor_tmp_6e2d1_18);
    eval.set_col(15, xor_col15);
    eval.set_sub_input_word(9, xor_col14);
    eval.set_sub_input_word(10, ms_8_bits_col10);
    eval.set_sub_input_word(11, xor_col15);
    eval.set_lookup_word(12, m31_112558620);
    eval.set_lookup_word(13, xor_col14);
    eval.set_lookup_word(14, ms_8_bits_col10);
    eval.set_lookup_word(15, xor_col15);
    let wg_v44 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_3[0]);
    let wg_v45 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_7[0]);
    let xor_tmp_6e2d1_20 = eval.u16_xor(wg_v44, wg_v45);
    let xor_col16 = eval.u16_as_m31(xor_tmp_6e2d1_20);
    eval.set_col(16, xor_col16);
    eval.set_sub_input_word(12, split_16_low_part_size_8_output_tmp_6e2d1_3[0]);
    eval.set_sub_input_word(13, split_16_low_part_size_8_output_tmp_6e2d1_7[0]);
    eval.set_sub_input_word(14, xor_col16);
    eval.set_lookup_word(16, m31_521092554);
    eval.set_lookup_word(17, split_16_low_part_size_8_output_tmp_6e2d1_3[0]);
    eval.set_lookup_word(18, split_16_low_part_size_8_output_tmp_6e2d1_7[0]);
    eval.set_lookup_word(19, xor_col16);
    let wg_v46 = eval.u16_from_m31(xor_col16);
    let wg_v47 = eval.u16_from_m31(split_16_low_part_size_8_output_tmp_6e2d1_11[0]);
    let xor_tmp_6e2d1_22 = eval.u16_xor(wg_v46, wg_v47);
    let xor_col17 = eval.u16_as_m31(xor_tmp_6e2d1_22);
    eval.set_col(17, xor_col17);
    eval.set_sub_input_word(15, xor_col16);
    eval.set_sub_input_word(16, split_16_low_part_size_8_output_tmp_6e2d1_11[0]);
    eval.set_sub_input_word(17, xor_col17);
    eval.set_lookup_word(20, m31_521092554);
    eval.set_lookup_word(21, xor_col16);
    eval.set_lookup_word(22, split_16_low_part_size_8_output_tmp_6e2d1_11[0]);
    eval.set_lookup_word(23, xor_col17);
    let wg_v48 = eval.u16_from_m31(ms_8_bits_col7);
    let wg_v49 = eval.u16_from_m31(ms_8_bits_col9);
    let xor_tmp_6e2d1_24 = eval.u16_xor(wg_v48, wg_v49);
    let xor_col18 = eval.u16_as_m31(xor_tmp_6e2d1_24);
    eval.set_col(18, xor_col18);
    eval.set_sub_input_word(18, ms_8_bits_col7);
    eval.set_sub_input_word(19, ms_8_bits_col9);
    eval.set_sub_input_word(20, xor_col18);
    eval.set_lookup_word(24, m31_521092554);
    eval.set_lookup_word(25, ms_8_bits_col7);
    eval.set_lookup_word(26, ms_8_bits_col9);
    eval.set_lookup_word(27, xor_col18);
    let wg_v50 = eval.u16_from_m31(xor_col18);
    let wg_v51 = eval.u16_from_m31(ms_8_bits_col11);
    let xor_tmp_6e2d1_26 = eval.u16_xor(wg_v50, wg_v51);
    let xor_col19 = eval.u16_as_m31(xor_tmp_6e2d1_26);
    eval.set_col(19, xor_col19);
    eval.set_sub_input_word(21, xor_col18);
    eval.set_sub_input_word(22, ms_8_bits_col11);
    eval.set_sub_input_word(23, xor_col19);
    eval.set_lookup_word(28, m31_521092554);
    eval.set_lookup_word(29, xor_col18);
    eval.set_lookup_word(30, ms_8_bits_col11);
    eval.set_lookup_word(31, xor_col19);
    let wg_v52 = eval.m31_mul(xor_col15, m31_256);
    let wg_v53 = eval.m31_add(xor_col13, wg_v52);
    let wg_v54 = eval.m31_mul(xor_col19, m31_256);
    let wg_v55 = eval.m31_add(xor_col17, wg_v54);
    let triple_xor32_output_tmp_6e2d1_28 = eval.u32_from_limbs(wg_v53, wg_v55);
    let enabler_col20 = eval.enabler();
    eval.set_col(20, enabler_col20);
    eval.set_lookup_word(32, m31_990559919);
    eval.set_lookup_word(33, input_limb_0_col0);
    eval.set_lookup_word(34, input_limb_1_col1);
    eval.set_lookup_word(35, input_limb_2_col2);
    eval.set_lookup_word(36, input_limb_3_col3);
    eval.set_lookup_word(37, input_limb_4_col4);
    eval.set_lookup_word(38, input_limb_5_col5);
    let wg_v56 = eval.u32_low(triple_xor32_output_tmp_6e2d1_28);
    let wg_v57 = eval.u16_as_m31(wg_v56);
    eval.set_lookup_word(39, wg_v57);
    let wg_v58 = eval.u32_high(triple_xor32_output_tmp_6e2d1_28);
    let wg_v59 = eval.u16_as_m31(wg_v58);
    eval.set_lookup_word(40, wg_v59);
    eval.set_lookup_word(41, m31_1);
    eval.set_lookup_word(42, enabler_col20);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `triple_xor_32_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
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
            |(row_index, (row, lookup_data, sub_component_inputs, triple_xor_32_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    None,
                    None,
                    vec![
                        triple_xor_32_input[0].simd,
                        triple_xor_32_input[1].simd,
                        triple_xor_32_input[2].simd,
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                triple_xor_32_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.verify_bitwise_xor_8_0 = [lw[0], lw[1], lw[2], lw[3]];
                *lookup_data.verify_bitwise_xor_8_1 = [lw[4], lw[5], lw[6], lw[7]];
                *lookup_data.verify_bitwise_xor_8_2 = [lw[8], lw[9], lw[10], lw[11]];
                *lookup_data.verify_bitwise_xor_8_3 = [lw[12], lw[13], lw[14], lw[15]];
                *lookup_data.verify_bitwise_xor_8_b_4 = [lw[16], lw[17], lw[18], lw[19]];
                *lookup_data.verify_bitwise_xor_8_b_5 = [lw[20], lw[21], lw[22], lw[23]];
                *lookup_data.verify_bitwise_xor_8_b_6 = [lw[24], lw[25], lw[26], lw[27]];
                *lookup_data.verify_bitwise_xor_8_b_7 = [lw[28], lw[29], lw[30], lw[31]];
                *lookup_data.triple_xor_32_8 = [
                    lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40],
                ];
                *lookup_data.mults_0 = lw[41];
                *lookup_data.mults_1 = lw[42];
                let sw = eval.sub_scratch();
                *sub_component_inputs.verify_bitwise_xor_8[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[0]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[3]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[4]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8_b[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[12]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[13]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[14]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8_b[1] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[15]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[16]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[17]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8_b[2] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[18]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[19]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[20]) },
                ];
                *sub_component_inputs.verify_bitwise_xor_8_b[3] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[21]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[22]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[23]) },
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
        verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
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
        let (trace, lookup_data, sub_component_inputs) =
            write_trace_generic_simd(packed_inputs, n_rows, verify_bitwise_xor_8_state);
        for inputs in sub_component_inputs.verify_bitwise_xor_8 {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.verify_bitwise_xor_8_b {
            add_inputs(
                verify_bitwise_xor_8_state,
                &inputs,
                inputs.len() * N_LANES,
                1,
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

/// Record the `triple_xor_32` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_triple_xor_32() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("triple_xor_32", 3, Some(4));
    triple_xor_32_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    43;
    verify_bitwise_xor_8_0: 4,
    verify_bitwise_xor_8_1: 4,
    verify_bitwise_xor_8_2: 4,
    verify_bitwise_xor_8_3: 4,
    verify_bitwise_xor_8_b_4: 4,
    verify_bitwise_xor_8_b_5: 4,
    verify_bitwise_xor_8_b_6: 4,
    verify_bitwise_xor_8_b_7: 4,
    triple_xor_32_8: 9,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    (
        "verify_bitwise_xor_8",
        0,
        "verify_bitwise_xor_8_state",
        0,
        0,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        1,
        "verify_bitwise_xor_8_state",
        0,
        3,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        2,
        "verify_bitwise_xor_8_state",
        0,
        6,
        3,
    ),
    (
        "verify_bitwise_xor_8",
        3,
        "verify_bitwise_xor_8_state",
        0,
        9,
        3,
    ),
    (
        "verify_bitwise_xor_8_b",
        0,
        "verify_bitwise_xor_8_state",
        1,
        12,
        3,
    ),
    (
        "verify_bitwise_xor_8_b",
        1,
        "verify_bitwise_xor_8_state",
        1,
        15,
        3,
    ),
    (
        "verify_bitwise_xor_8_b",
        2,
        "verify_bitwise_xor_8_state",
        1,
        18,
        3,
    ),
    (
        "verify_bitwise_xor_8_b",
        3,
        "verify_bitwise_xor_8_state",
        1,
        21,
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
        "verify_bitwise_xor_8_0",
        "mults_0",
        false,
        "verify_bitwise_xor_8_1",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_8_2",
        "mults_0",
        false,
        "verify_bitwise_xor_8_3",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_8_b_4",
        "mults_0",
        false,
        "verify_bitwise_xor_8_b_5",
        "mults_0",
        false,
    ),
    (
        "verify_bitwise_xor_8_b_6",
        "mults_0",
        false,
        "verify_bitwise_xor_8_b_7",
        "mults_0",
        false,
    ),
    ("triple_xor_32_8", "mults_1", true, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.verify_bitwise_xor_8_0
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_1
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_2
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_3
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_b_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_b_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_b_6
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.verify_bitwise_xor_8_b_7
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.triple_xor_32_8.iter().flatten().copied().collect(),
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
        sci.verify_bitwise_xor_8_b[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8_b[1]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8_b[2]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.verify_bitwise_xor_8_b[3]
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
    inputs: Vec<PackedInputType>,
    n_rows: usize,
    verify_bitwise_xor_8_state: &verify_bitwise_xor_8::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) =
        write_trace_simd(inputs.clone(), n_rows.clone(), verify_bitwise_xor_8_state);
    let (trace_g, ld_g, sci_g) =
        write_trace_generic_simd(inputs, n_rows, verify_bitwise_xor_8_state);
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
    verify_bitwise_xor_8_0: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_1: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_2: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_3: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_b_4: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_b_5: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_b_6: Vec<[PackedM31; 4]>,
    verify_bitwise_xor_8_b_7: Vec<[PackedM31; 4]>,
    triple_xor_32_8: Vec<[PackedM31; 9]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    verify_bitwise_xor_8_0: 4,
    verify_bitwise_xor_8_1: 4,
    verify_bitwise_xor_8_2: 4,
    verify_bitwise_xor_8_3: 4,
    verify_bitwise_xor_8_b_4: 4,
    verify_bitwise_xor_8_b_5: 4,
    verify_bitwise_xor_8_b_6: 4,
    verify_bitwise_xor_8_b_7: 4,
    triple_xor_32_8: 9,
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
            &self.lookup_data.verify_bitwise_xor_8_0,
            &self.lookup_data.verify_bitwise_xor_8_1,
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
            &self.lookup_data.verify_bitwise_xor_8_2,
            &self.lookup_data.verify_bitwise_xor_8_3,
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
            &self.lookup_data.verify_bitwise_xor_8_b_4,
            &self.lookup_data.verify_bitwise_xor_8_b_5,
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
            &self.lookup_data.verify_bitwise_xor_8_b_6,
            &self.lookup_data.verify_bitwise_xor_8_b_7,
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
            &self.lookup_data.triple_xor_32_8,
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
