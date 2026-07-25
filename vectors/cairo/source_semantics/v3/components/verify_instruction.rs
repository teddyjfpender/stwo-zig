// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::verify_instruction::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{
    memory_address_to_id, memory_id_to_big, range_check_4_3, range_check_7_2_5,
};
use crate::witness::prelude::*;

pub type InputType = (M31, [M31; 3], [M31; 2], M31);
pub type PackedInputType = (PackedM31, [PackedM31; 3], [PackedM31; 2], PackedM31);

#[derive(Default)]
pub struct ClaimGenerator {
    pub mults: DashMap<InputType, AtomicU32>,
}

impl ClaimGenerator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn write_trace(
        self,
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        range_check_4_3_state: &range_check_4_3::ClaimGenerator,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut inputs_mults = self
            .mults
            .iter()
            .map(|entry| (*entry.key(), M31(entry.value().load(Ordering::Relaxed))))
            .collect::<Vec<_>>();

        inputs_mults.sort_by_key(|(input, _)| input.0);

        let (mut inputs, mut mults) = inputs_mults.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();

        let n_rows = inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();

        inputs.resize(size, *inputs.first().unwrap());
        mults.resize(size, M31::zero());

        let packed_inputs = pack_values(&inputs);
        let packed_mults = pack_values(&mults);

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            packed_inputs,
            vec![packed_mults],
            range_check_7_2_5_state,
            range_check_4_3_state,
            memory_address_to_id_state,
            memory_id_to_big_state,
        );
        for inputs in sub_component_inputs.range_check_7_2_5 {
            add_inputs(range_check_7_2_5_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_4_3 {
            add_inputs(range_check_4_3_state, &inputs, inputs.len() * N_LANES, 0);
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

impl AddInputs for ClaimGenerator {
    type PackedInputType = PackedInputType;
    type InputType = InputType;

    fn add_packed_inputs(&self, packed_inputs: &[PackedInputType], _relation_index: usize) {
        let merged: HashMap<InputType, u32> = packed_inputs
            .par_iter()
            .flat_map(|p| p.unpack())
            .fold_with(HashMap::new(), |mut local, input| {
                *local.entry(input).or_insert(0) += 1;
                local
            })
            .reduce(HashMap::new, |mut a, b| {
                for (k, v) in b {
                    *a.entry(k).or_insert(0) += v;
                }
                a
            });

        for (k, v) in merged {
            self.mults
                .entry(k)
                .or_insert_with(|| AtomicU32::new(0))
                .fetch_add(v, Ordering::Relaxed);
        }
    }
    fn add_input(&self, input: &InputType, _relation_index: usize) {
        self.mults
            .entry(*input)
            .or_insert_with(|| AtomicU32::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Uninitialized, IterMut, ParIterMut)]
struct SubComponentInputs {
    range_check_7_2_5: [Vec<range_check_7_2_5::PackedInputType>; 1],
    range_check_4_3: [Vec<range_check_4_3::PackedInputType>; 1],
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 1],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 1],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    inputs: Vec<PackedInputType>,
    mults: Vec<Vec<PackedM31>>,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    range_check_4_3_state: &range_check_4_3::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
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
    let M31_1567323731 = PackedM31::broadcast(M31::from(1567323731));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_371240602 = PackedM31::broadcast(M31::from(371240602));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_13 = PackedUInt16::broadcast(UInt16::from(13));
    let UInt16_15 = PackedUInt16::broadcast(UInt16::from(15));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
    let UInt16_4 = PackedUInt16::broadcast(UInt16::from(4));
    let UInt16_511 = PackedUInt16::broadcast(UInt16::from(511));
    let UInt16_9 = PackedUInt16::broadcast(UInt16::from(9));

    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, verify_instruction_input))| {
                let input_pc_col0 = verify_instruction_input.0;
                *row[0] = input_pc_col0;
                let input_offset0_col1 = verify_instruction_input.1[0];
                *row[1] = input_offset0_col1;
                let input_offset1_col2 = verify_instruction_input.1[1];
                *row[2] = input_offset1_col2;
                let input_offset2_col3 = verify_instruction_input.1[2];
                *row[3] = input_offset2_col3;
                let input_inst_felt5_high_col4 = verify_instruction_input.2[0];
                *row[4] = input_inst_felt5_high_col4;
                let input_inst_felt6_col5 = verify_instruction_input.2[1];
                *row[5] = input_inst_felt6_col5;
                let input_opcode_extension_col6 = verify_instruction_input.3;
                *row[6] = input_opcode_extension_col6;

                // Encode Offsets.

                let offset0_low_tmp_40a8f_0 =
                    ((PackedUInt16::from_m31(input_offset0_col1)) & (UInt16_511));
                let offset0_low_col7 = offset0_low_tmp_40a8f_0.as_m31();
                *row[7] = offset0_low_col7;
                let offset0_mid_tmp_40a8f_1 =
                    ((PackedUInt16::from_m31(input_offset0_col1)) >> (UInt16_9));
                let offset0_mid_col8 = offset0_mid_tmp_40a8f_1.as_m31();
                *row[8] = offset0_mid_col8;
                let offset1_low_tmp_40a8f_2 =
                    ((PackedUInt16::from_m31(input_offset1_col2)) & (UInt16_3));
                let offset1_low_col9 = offset1_low_tmp_40a8f_2.as_m31();
                *row[9] = offset1_low_col9;
                let offset1_mid_tmp_40a8f_3 =
                    (((PackedUInt16::from_m31(input_offset1_col2)) >> (UInt16_2)) & (UInt16_511));
                let offset1_mid_col10 = offset1_mid_tmp_40a8f_3.as_m31();
                *row[10] = offset1_mid_col10;
                let offset1_high_tmp_40a8f_4 =
                    ((PackedUInt16::from_m31(input_offset1_col2)) >> (UInt16_11));
                let offset1_high_col11 = offset1_high_tmp_40a8f_4.as_m31();
                *row[11] = offset1_high_col11;
                let offset2_low_tmp_40a8f_5 =
                    ((PackedUInt16::from_m31(input_offset2_col3)) & (UInt16_15));
                let offset2_low_col12 = offset2_low_tmp_40a8f_5.as_m31();
                *row[12] = offset2_low_col12;
                let offset2_mid_tmp_40a8f_6 =
                    (((PackedUInt16::from_m31(input_offset2_col3)) >> (UInt16_4)) & (UInt16_511));
                let offset2_mid_col13 = offset2_mid_tmp_40a8f_6.as_m31();
                *row[13] = offset2_mid_col13;
                let offset2_high_tmp_40a8f_7 =
                    ((PackedUInt16::from_m31(input_offset2_col3)) >> (UInt16_13));
                let offset2_high_col14 = offset2_high_tmp_40a8f_7.as_m31();
                *row[14] = offset2_high_col14;
                *sub_component_inputs.range_check_7_2_5[0] =
                    [offset0_mid_col8, offset1_low_col9, offset1_high_col11];
                *lookup_data.range_check_7_2_5_0 = [
                    M31_371240602,
                    offset0_mid_col8,
                    offset1_low_col9,
                    offset1_high_col11,
                ];
                *sub_component_inputs.range_check_4_3[0] = [offset2_low_col12, offset2_high_col14];
                *lookup_data.range_check_4_3_1 =
                    [M31_1567323731, offset2_low_col12, offset2_high_col14];
                let encode_offsets_output_tmp_40a8f_8 = [
                    offset0_low_col7,
                    ((offset0_mid_col8) + ((offset1_low_col9) * (M31_128))),
                    offset1_mid_col10,
                    ((offset1_high_col11) + ((offset2_low_col12) * (M31_32))),
                    offset2_mid_col13,
                    offset2_high_col14,
                ];

                // Mem Verify.

                // Read Id.

                let memory_address_to_id_value_tmp_40a8f_9 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let instruction_id_col15 = memory_address_to_id_value_tmp_40a8f_9;
                *row[15] = instruction_id_col15;
                *sub_component_inputs.memory_address_to_id[0] = input_pc_col0;
                *lookup_data.memory_address_to_id_2 =
                    [M31_1444891767, input_pc_col0, instruction_id_col15];

                *sub_component_inputs.memory_id_to_big[0] = instruction_id_col15;
                *lookup_data.memory_id_to_big_3 = [
                    M31_1662111297,
                    instruction_id_col15,
                    offset0_low_col7,
                    encode_offsets_output_tmp_40a8f_8[1],
                    offset1_mid_col10,
                    encode_offsets_output_tmp_40a8f_8[3],
                    offset2_mid_col13,
                    ((offset2_high_col14) + (input_inst_felt5_high_col4)),
                    input_inst_felt6_col5,
                    input_opcode_extension_col6,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
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

                let multiplicity_0_col16 = *mults[0].get(row_index).unwrap_or(&PackedM31::zero());
                *row[16] = multiplicity_0_col16;
                *lookup_data.verify_instruction_4 = [
                    M31_1719106205,
                    input_pc_col0,
                    input_offset0_col1,
                    input_offset1_col2,
                    input_offset2_col3,
                    input_inst_felt5_high_col4,
                    input_inst_felt6_col5,
                    input_opcode_extension_col6,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = multiplicity_0_col16;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `verify_instruction` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     range_check_7_2_5_0[4] 0..3
//     range_check_4_3_1[3] 4..6
//     memory_address_to_id_2[3] 7..9
//     memory_id_to_big_3[30] 10..39
//     verify_instruction_4[8] 40..47
//     mults_0 48
//     mults_1 49
//     (50 words)
//   SUB-INPUT words:
//     range_check_7_2_5[0] 0..2
//     range_check_4_3[0] 3..4
//     memory_address_to_id[0] 5
//     memory_id_to_big[0] 6
//     (7 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 50;
pub(crate) const N_SUB_INPUT_WORDS: usize = 7;

/// The per-row `verify_instruction` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn verify_instruction_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_32 = eval.m31_const(32);
    let m31_128 = eval.m31_const(128);
    let m31_371240602 = eval.m31_const(371240602);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1567323731 = eval.m31_const(1567323731);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let input_pc_col0 = eval.input(0);
    eval.set_col(0, input_pc_col0);
    let input_offset0_col1 = eval.input(1);
    eval.set_col(1, input_offset0_col1);
    let input_offset1_col2 = eval.input(2);
    eval.set_col(2, input_offset1_col2);
    let input_offset2_col3 = eval.input(3);
    eval.set_col(3, input_offset2_col3);
    let input_inst_felt5_high_col4 = eval.input(4);
    eval.set_col(4, input_inst_felt5_high_col4);
    let input_inst_felt6_col5 = eval.input(5);
    eval.set_col(5, input_inst_felt6_col5);
    let input_opcode_extension_col6 = eval.input(6);
    eval.set_col(6, input_opcode_extension_col6);
    let wg_v0 = eval.u16_from_m31(input_offset0_col1);
    let offset0_low_tmp_40a8f_0 = eval.u16_and(wg_v0, 511);
    let offset0_low_col7 = eval.u16_as_m31(offset0_low_tmp_40a8f_0);
    eval.set_col(7, offset0_low_col7);
    let wg_v1 = eval.u16_from_m31(input_offset0_col1);
    let offset0_mid_tmp_40a8f_1 = eval.u16_shr(wg_v1, 9);
    let offset0_mid_col8 = eval.u16_as_m31(offset0_mid_tmp_40a8f_1);
    eval.set_col(8, offset0_mid_col8);
    let wg_v2 = eval.u16_from_m31(input_offset1_col2);
    let offset1_low_tmp_40a8f_2 = eval.u16_and(wg_v2, 3);
    let offset1_low_col9 = eval.u16_as_m31(offset1_low_tmp_40a8f_2);
    eval.set_col(9, offset1_low_col9);
    let wg_v3 = eval.u16_from_m31(input_offset1_col2);
    let wg_v4 = eval.u16_shr(wg_v3, 2);
    let offset1_mid_tmp_40a8f_3 = eval.u16_and(wg_v4, 511);
    let offset1_mid_col10 = eval.u16_as_m31(offset1_mid_tmp_40a8f_3);
    eval.set_col(10, offset1_mid_col10);
    let wg_v5 = eval.u16_from_m31(input_offset1_col2);
    let offset1_high_tmp_40a8f_4 = eval.u16_shr(wg_v5, 11);
    let offset1_high_col11 = eval.u16_as_m31(offset1_high_tmp_40a8f_4);
    eval.set_col(11, offset1_high_col11);
    let wg_v6 = eval.u16_from_m31(input_offset2_col3);
    let offset2_low_tmp_40a8f_5 = eval.u16_and(wg_v6, 15);
    let offset2_low_col12 = eval.u16_as_m31(offset2_low_tmp_40a8f_5);
    eval.set_col(12, offset2_low_col12);
    let wg_v7 = eval.u16_from_m31(input_offset2_col3);
    let wg_v8 = eval.u16_shr(wg_v7, 4);
    let offset2_mid_tmp_40a8f_6 = eval.u16_and(wg_v8, 511);
    let offset2_mid_col13 = eval.u16_as_m31(offset2_mid_tmp_40a8f_6);
    eval.set_col(13, offset2_mid_col13);
    let wg_v9 = eval.u16_from_m31(input_offset2_col3);
    let offset2_high_tmp_40a8f_7 = eval.u16_shr(wg_v9, 13);
    let offset2_high_col14 = eval.u16_as_m31(offset2_high_tmp_40a8f_7);
    eval.set_col(14, offset2_high_col14);
    eval.set_sub_input_word(0, offset0_mid_col8);
    eval.set_sub_input_word(1, offset1_low_col9);
    eval.set_sub_input_word(2, offset1_high_col11);
    eval.set_lookup_word(0, m31_371240602);
    eval.set_lookup_word(1, offset0_mid_col8);
    eval.set_lookup_word(2, offset1_low_col9);
    eval.set_lookup_word(3, offset1_high_col11);
    eval.set_sub_input_word(3, offset2_low_col12);
    eval.set_sub_input_word(4, offset2_high_col14);
    eval.set_lookup_word(4, m31_1567323731);
    eval.set_lookup_word(5, offset2_low_col12);
    eval.set_lookup_word(6, offset2_high_col14);
    let wg_v10 = eval.m31_mul(offset1_low_col9, m31_128);
    let wg_v11 = eval.m31_add(offset0_mid_col8, wg_v10);
    let wg_v12 = eval.m31_mul(offset2_low_col12, m31_32);
    let wg_v13 = eval.m31_add(offset1_high_col11, wg_v12);
    let encode_offsets_output_tmp_40a8f_8 = [
        offset0_low_col7,
        wg_v11,
        offset1_mid_col10,
        wg_v13,
        offset2_mid_col13,
        offset2_high_col14,
    ];
    let memory_address_to_id_value_tmp_40a8f_9 = eval.mem_addr_to_id(input_pc_col0);
    let instruction_id_col15 = memory_address_to_id_value_tmp_40a8f_9;
    eval.set_col(15, instruction_id_col15);
    eval.set_sub_input_word(5, input_pc_col0);
    eval.set_lookup_word(7, m31_1444891767);
    eval.set_lookup_word(8, input_pc_col0);
    eval.set_lookup_word(9, instruction_id_col15);
    eval.set_sub_input_word(6, instruction_id_col15);
    eval.set_lookup_word(10, m31_1662111297);
    eval.set_lookup_word(11, instruction_id_col15);
    eval.set_lookup_word(12, offset0_low_col7);
    eval.set_lookup_word(13, encode_offsets_output_tmp_40a8f_8[1]);
    eval.set_lookup_word(14, offset1_mid_col10);
    eval.set_lookup_word(15, encode_offsets_output_tmp_40a8f_8[3]);
    eval.set_lookup_word(16, offset2_mid_col13);
    let wg_v14 = eval.m31_add(offset2_high_col14, input_inst_felt5_high_col4);
    eval.set_lookup_word(17, wg_v14);
    eval.set_lookup_word(18, input_inst_felt6_col5);
    eval.set_lookup_word(19, input_opcode_extension_col6);
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
    let multiplicity_0_col16 = eval.input(9);
    eval.set_col(16, multiplicity_0_col16);
    eval.set_lookup_word(40, m31_1719106205);
    eval.set_lookup_word(41, input_pc_col0);
    eval.set_lookup_word(42, input_offset0_col1);
    eval.set_lookup_word(43, input_offset1_col2);
    eval.set_lookup_word(44, input_offset2_col3);
    eval.set_lookup_word(45, input_inst_felt5_high_col4);
    eval.set_lookup_word(46, input_inst_felt6_col5);
    eval.set_lookup_word(47, input_opcode_extension_col6);
    eval.set_lookup_word(48, m31_1);
    eval.set_lookup_word(49, multiplicity_0_col16);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `verify_instruction_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    inputs: Vec<PackedInputType>,
    mults: Vec<Vec<PackedM31>>,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    range_check_4_3_state: &range_check_4_3::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
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
    let enabler_col = Enabler::new(0);
    (
        trace.par_iter_mut(),
        lookup_data.par_iter_mut(),
        sub_component_inputs.par_iter_mut(),
        inputs.into_par_iter(),
    )
        .into_par_iter()
        .enumerate()
        .for_each(
            |(row_index, (row, lookup_data, sub_component_inputs, verify_instruction_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    vec![
                        verify_instruction_input.0.into_simd(),
                        verify_instruction_input.1[0].into_simd(),
                        verify_instruction_input.1[1].into_simd(),
                        verify_instruction_input.1[2].into_simd(),
                        verify_instruction_input.2[0].into_simd(),
                        verify_instruction_input.2[1].into_simd(),
                        verify_instruction_input.3.into_simd(),
                        Simd::splat(0),
                        Simd::splat(0),
                        mults[0]
                            .get(row_index)
                            .copied()
                            .unwrap_or(PackedM31::zero())
                            .into_simd(),
                    ],
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                verify_instruction_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.range_check_7_2_5_0 = [lw[0], lw[1], lw[2], lw[3]];
                *lookup_data.range_check_4_3_1 = [lw[4], lw[5], lw[6]];
                *lookup_data.memory_address_to_id_2 = [lw[7], lw[8], lw[9]];
                *lookup_data.memory_id_to_big_3 = [
                    lw[10], lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19],
                    lw[20], lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29],
                    lw[30], lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39],
                ];
                *lookup_data.verify_instruction_4 = [
                    lw[40], lw[41], lw[42], lw[43], lw[44], lw[45], lw[46], lw[47],
                ];
                *lookup_data.mults_0 = lw[48];
                *lookup_data.mults_1 = lw[49];
                let sw = eval.sub_scratch();
                *sub_component_inputs.range_check_7_2_5[0] = [
                    unsafe { PackedM31::from_simd_unchecked(sw[0]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[1]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[2]) },
                ];
                *sub_component_inputs.range_check_4_3[0] =
                    [unsafe { PackedM31::from_simd_unchecked(sw[3]) }, unsafe {
                        PackedM31::from_simd_unchecked(sw[4])
                    }];
                *sub_component_inputs.memory_address_to_id[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[5]) };
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) };
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
        range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
        range_check_4_3_state: &range_check_4_3::ClaimGenerator,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let mut inputs_mults = self
            .mults
            .iter()
            .map(|entry| (*entry.key(), M31(entry.value().load(Ordering::Relaxed))))
            .collect::<Vec<_>>();
        inputs_mults.sort_by_key(|(input, _)| input.0);
        let (mut inputs, mut mults) = inputs_mults.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
        let n_rows = inputs.len();
        assert_ne!(n_rows, 0);
        let size = std::cmp::max(n_rows.next_power_of_two(), N_LANES);
        let log_size = size.ilog2();
        inputs.resize(size, *inputs.first().unwrap());
        mults.resize(size, M31::zero());
        let packed_inputs = pack_values(&inputs);
        let packed_mults = pack_values(&mults);
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            packed_inputs,
            vec![packed_mults],
            range_check_7_2_5_state,
            range_check_4_3_state,
            memory_address_to_id_state,
            memory_id_to_big_state,
        );
        for inputs in sub_component_inputs.range_check_7_2_5 {
            add_inputs(range_check_7_2_5_state, &inputs, inputs.len() * N_LANES, 0);
        }
        for inputs in sub_component_inputs.range_check_4_3 {
            add_inputs(range_check_4_3_state, &inputs, inputs.len() * N_LANES, 0);
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

/// Record the `verify_instruction` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_verify_instruction() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("verify_instruction", 7, Some(8));
    verify_instruction_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    50;
    range_check_7_2_5_0: 4,
    range_check_4_3_1: 3,
    memory_address_to_id_2: 3,
    memory_id_to_big_3: 30,
    verify_instruction_4: 8,
    mults_0: scalar,
    mults_1: scalar,
}

/// Device-DAG feed layout (facts, DECLARATION order): one entry per
/// `SubComponentInputs` instance — (field, instance, downstream state
/// param, relation_index, flat word base, words per instance).
#[allow(dead_code)]
pub(crate) const SUB_FEED_LAYOUT: &[(&str, usize, &str, u32, usize, usize)] = &[
    ("range_check_7_2_5", 0, "range_check_7_2_5_state", 0, 0, 3),
    ("range_check_4_3", 0, "range_check_4_3_state", 0, 3, 2),
    (
        "memory_address_to_id",
        0,
        "memory_address_to_id_state",
        0,
        5,
        1,
    ),
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 6, 1),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[
    (
        "range_check_7_2_5_0",
        "mults_0",
        false,
        "range_check_4_3_1",
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
    ("verify_instruction_4", "mults_1", true, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.range_check_7_2_5_0.iter().flatten().copied().collect(),
        ld.range_check_4_3_1.iter().flatten().copied().collect(),
        ld.memory_address_to_id_2
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_3.iter().flatten().copied().collect(),
        ld.verify_instruction_4.iter().flatten().copied().collect(),
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
        sci.range_check_7_2_5[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd(), t[2].into_simd()])
            .collect::<Vec<_>>(),
        sci.range_check_4_3[0]
            .iter()
            .flat_map(|t| vec![t[0].into_simd(), t[1].into_simd()])
            .collect::<Vec<_>>(),
        sci.memory_address_to_id[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[0]
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
    mults: Vec<Vec<PackedM31>>,
    range_check_7_2_5_state: &range_check_7_2_5::ClaimGenerator,
    range_check_4_3_state: &range_check_4_3::ClaimGenerator,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        inputs.clone(),
        mults.clone(),
        range_check_7_2_5_state,
        range_check_4_3_state,
        memory_address_to_id_state,
        memory_id_to_big_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        inputs,
        mults,
        range_check_7_2_5_state,
        range_check_4_3_state,
        memory_address_to_id_state,
        memory_id_to_big_state,
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
    range_check_7_2_5_0: Vec<[PackedM31; 4]>,
    range_check_4_3_1: Vec<[PackedM31; 3]>,
    memory_address_to_id_2: Vec<[PackedM31; 3]>,
    memory_id_to_big_3: Vec<[PackedM31; 30]>,
    verify_instruction_4: Vec<[PackedM31; 8]>,
    mults_0: Vec<PackedM31>,
    mults_1: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    range_check_7_2_5_0: 4,
    range_check_4_3_1: 3,
    memory_address_to_id_2: 3,
    memory_id_to_big_3: 30,
    verify_instruction_4: 8,
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
            &self.lookup_data.range_check_7_2_5_0,
            &self.lookup_data.range_check_4_3_1,
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

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.verify_instruction_4,
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
