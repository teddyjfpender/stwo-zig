// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::ret_opcode::{Claim, InteractionClaim, N_TRACE_COLUMNS};
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 2],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 2],
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
    let M31_130 = PackedM31::broadcast(M31::from(130));
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_2147483645 = PackedM31::broadcast(M31::from(2147483645));
    let M31_2147483646 = PackedM31::broadcast(M31::from(2147483646));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_32766 = PackedM31::broadcast(M31::from(32766));
    let M31_32767 = PackedM31::broadcast(M31::from(32767));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_88 = PackedM31::broadcast(M31::from(88));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
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
            |(row_index, (row, lookup_data, sub_component_inputs, ret_opcode_input))| {
                let input_pc_col0 = ret_opcode_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = ret_opcode_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = ret_opcode_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_3f5e2_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_3f5e2_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_3f5e2_0);
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [M31_32766, M31_32767, M31_32767],
                    [M31_88, M31_130],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    M31_32766,
                    M31_32767,
                    M31_32767,
                    M31_88,
                    M31_130,
                    M31_0,
                ];
                let decode_instruction_a4d88_output_tmp_3f5e2_2 = (
                    [M31_2147483645, M31_2147483646, M31_2147483646],
                    [
                        M31_1, M31_1, M31_0, M31_1, M31_0, M31_0, M31_0, M31_1, M31_0, M31_0,
                        M31_0, M31_0, M31_0, M31_1, M31_0,
                    ],
                    M31_0,
                );

                // Read Positive Num Bits 29.

                // Read Id.

                let memory_address_to_id_value_tmp_3f5e2_3 =
                    memory_address_to_id_state.deduce_output(((input_fp_col2) - (M31_1)));
                let next_pc_id_col3 = memory_address_to_id_value_tmp_3f5e2_3;
                *row[3] = next_pc_id_col3;
                *sub_component_inputs.memory_address_to_id[0] = ((input_fp_col2) - (M31_1));
                *lookup_data.memory_address_to_id_1 =
                    [M31_1444891767, ((input_fp_col2) - (M31_1)), next_pc_id_col3];

                // Read Positive Known Id Num Bits 29.

                let memory_id_to_big_value_tmp_3f5e2_5 =
                    memory_id_to_big_state.deduce_output(next_pc_id_col3);
                let next_pc_limb_0_col4 = memory_id_to_big_value_tmp_3f5e2_5.get_m31(0);
                *row[4] = next_pc_limb_0_col4;
                let next_pc_limb_1_col5 = memory_id_to_big_value_tmp_3f5e2_5.get_m31(1);
                *row[5] = next_pc_limb_1_col5;
                let next_pc_limb_2_col6 = memory_id_to_big_value_tmp_3f5e2_5.get_m31(2);
                *row[6] = next_pc_limb_2_col6;
                let next_pc_limb_3_col7 = memory_id_to_big_value_tmp_3f5e2_5.get_m31(3);
                *row[7] = next_pc_limb_3_col7;

                // Range Check Last Limb Bits In Ms Limb 2.

                // Cond Range Check 2.

                let partial_limb_msb_tmp_3f5e2_6 =
                    (((PackedUInt16::from_m31(next_pc_limb_3_col7)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col8 = partial_limb_msb_tmp_3f5e2_6.as_m31();
                *row[8] = partial_limb_msb_col8;

                *sub_component_inputs.memory_id_to_big[0] = next_pc_id_col3;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    next_pc_id_col3,
                    next_pc_limb_0_col4,
                    next_pc_limb_1_col5,
                    next_pc_limb_2_col6,
                    next_pc_limb_3_col7,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
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
                let read_positive_known_id_num_bits_29_output_tmp_3f5e2_8 =
                    PackedFelt252::from_limbs([
                        next_pc_limb_0_col4,
                        next_pc_limb_1_col5,
                        next_pc_limb_2_col6,
                        next_pc_limb_3_col7,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
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

                let read_positive_num_bits_29_output_tmp_3f5e2_9 = (
                    read_positive_known_id_num_bits_29_output_tmp_3f5e2_8,
                    next_pc_id_col3,
                );

                // Read Positive Num Bits 29.

                // Read Id.

                let memory_address_to_id_value_tmp_3f5e2_10 =
                    memory_address_to_id_state.deduce_output(((input_fp_col2) - (M31_2)));
                let next_fp_id_col9 = memory_address_to_id_value_tmp_3f5e2_10;
                *row[9] = next_fp_id_col9;
                *sub_component_inputs.memory_address_to_id[1] = ((input_fp_col2) - (M31_2));
                *lookup_data.memory_address_to_id_3 =
                    [M31_1444891767, ((input_fp_col2) - (M31_2)), next_fp_id_col9];

                // Read Positive Known Id Num Bits 29.

                let memory_id_to_big_value_tmp_3f5e2_12 =
                    memory_id_to_big_state.deduce_output(next_fp_id_col9);
                let next_fp_limb_0_col10 = memory_id_to_big_value_tmp_3f5e2_12.get_m31(0);
                *row[10] = next_fp_limb_0_col10;
                let next_fp_limb_1_col11 = memory_id_to_big_value_tmp_3f5e2_12.get_m31(1);
                *row[11] = next_fp_limb_1_col11;
                let next_fp_limb_2_col12 = memory_id_to_big_value_tmp_3f5e2_12.get_m31(2);
                *row[12] = next_fp_limb_2_col12;
                let next_fp_limb_3_col13 = memory_id_to_big_value_tmp_3f5e2_12.get_m31(3);
                *row[13] = next_fp_limb_3_col13;

                // Range Check Last Limb Bits In Ms Limb 2.

                // Cond Range Check 2.

                let partial_limb_msb_tmp_3f5e2_13 =
                    (((PackedUInt16::from_m31(next_fp_limb_3_col13)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col14 = partial_limb_msb_tmp_3f5e2_13.as_m31();
                *row[14] = partial_limb_msb_col14;

                *sub_component_inputs.memory_id_to_big[1] = next_fp_id_col9;
                *lookup_data.memory_id_to_big_4 = [
                    M31_1662111297,
                    next_fp_id_col9,
                    next_fp_limb_0_col10,
                    next_fp_limb_1_col11,
                    next_fp_limb_2_col12,
                    next_fp_limb_3_col13,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
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
                let read_positive_known_id_num_bits_29_output_tmp_3f5e2_15 =
                    PackedFelt252::from_limbs([
                        next_fp_limb_0_col10,
                        next_fp_limb_1_col11,
                        next_fp_limb_2_col12,
                        next_fp_limb_3_col13,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
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

                let read_positive_num_bits_29_output_tmp_3f5e2_16 = (
                    read_positive_known_id_num_bits_29_output_tmp_3f5e2_15,
                    next_fp_id_col9,
                );

                let enabler_col15 = enabler_col.packed_at(row_index);
                *row[15] = enabler_col15;
                *lookup_data.opcodes_5 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_6 = [
                    M31_428564188,
                    ((((next_pc_limb_0_col4) + ((next_pc_limb_1_col5) * (M31_512)))
                        + ((next_pc_limb_2_col6) * (M31_262144)))
                        + ((next_pc_limb_3_col7) * (M31_134217728))),
                    input_ap_col1,
                    ((((next_fp_limb_0_col10) + ((next_fp_limb_1_col11) * (M31_512)))
                        + ((next_fp_limb_2_col12) * (M31_262144)))
                        + ((next_fp_limb_3_col13) * (M31_134217728))),
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col15;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `ret_opcode` — mechanical rewrite of
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
//     opcodes_5[4] 74..77
//     opcodes_6[4] 78..81
//     mults_0 82
//     mults_1 83
//     (84 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     memory_id_to_big[0] 9
//     memory_id_to_big[1] 10
//     (11 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 84;
pub(crate) const N_SUB_INPUT_WORDS: usize = 11;

/// The per-row `ret_opcode` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn ret_opcode_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_88 = eval.m31_const(88);
    let m31_130 = eval.m31_const(130);
    let m31_512 = eval.m31_const(512);
    let m31_32766 = eval.m31_const(32766);
    let m31_32767 = eval.m31_const(32767);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let m31_2147483645 = eval.m31_const(2147483645);
    let m31_2147483646 = eval.m31_const(2147483646);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_3f5e2_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_3f5e2_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_3f5e2_0);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, m31_32766);
    eval.set_sub_input_word(2, m31_32767);
    eval.set_sub_input_word(3, m31_32767);
    eval.set_sub_input_word(4, m31_88);
    eval.set_sub_input_word(5, m31_130);
    eval.set_sub_input_word(6, m31_0);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, m31_32766);
    eval.set_lookup_word(3, m31_32767);
    eval.set_lookup_word(4, m31_32767);
    eval.set_lookup_word(5, m31_88);
    eval.set_lookup_word(6, m31_130);
    eval.set_lookup_word(7, m31_0);
    let decode_instruction_a4d88_output_tmp_3f5e2_2 = (
        [m31_2147483645, m31_2147483646, m31_2147483646],
        [
            m31_1, m31_1, m31_0, m31_1, m31_0, m31_0, m31_0, m31_1, m31_0, m31_0, m31_0, m31_0,
            m31_0, m31_1, m31_0,
        ],
        m31_0,
    );
    let wg_v0 = eval.m31_sub(input_fp_col2, m31_1);
    let memory_address_to_id_value_tmp_3f5e2_3 = eval.mem_addr_to_id(wg_v0);
    let next_pc_id_col3 = memory_address_to_id_value_tmp_3f5e2_3;
    eval.set_col(3, next_pc_id_col3);
    let wg_v1 = eval.m31_sub(input_fp_col2, m31_1);
    eval.set_sub_input_word(7, wg_v1);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v2 = eval.m31_sub(input_fp_col2, m31_1);
    eval.set_lookup_word(9, wg_v2);
    eval.set_lookup_word(10, next_pc_id_col3);
    let memory_id_to_big_value_tmp_3f5e2_5 = eval.mem_id_to_value(next_pc_id_col3);
    let next_pc_limb_0_col4 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_5.clone(), 0);
    eval.set_col(4, next_pc_limb_0_col4);
    let next_pc_limb_1_col5 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_5.clone(), 1);
    eval.set_col(5, next_pc_limb_1_col5);
    let next_pc_limb_2_col6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_5.clone(), 2);
    eval.set_col(6, next_pc_limb_2_col6);
    let next_pc_limb_3_col7 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_5.clone(), 3);
    eval.set_col(7, next_pc_limb_3_col7);
    let wg_v3 = eval.u16_from_m31(next_pc_limb_3_col7);
    let wg_v4 = eval.u16_and(wg_v3, 2);
    let partial_limb_msb_tmp_3f5e2_6 = eval.u16_shr(wg_v4, 1);
    let partial_limb_msb_col8 = eval.u16_as_m31(partial_limb_msb_tmp_3f5e2_6);
    eval.set_col(8, partial_limb_msb_col8);
    eval.set_sub_input_word(9, next_pc_id_col3);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, next_pc_id_col3);
    eval.set_lookup_word(13, next_pc_limb_0_col4);
    eval.set_lookup_word(14, next_pc_limb_1_col5);
    eval.set_lookup_word(15, next_pc_limb_2_col6);
    eval.set_lookup_word(16, next_pc_limb_3_col7);
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
    let read_positive_known_id_num_bits_29_output_tmp_3f5e2_8 = eval.felt_from_limbs([
        next_pc_limb_0_col4,
        next_pc_limb_1_col5,
        next_pc_limb_2_col6,
        next_pc_limb_3_col7,
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
    let read_positive_num_bits_29_output_tmp_3f5e2_9 = (
        read_positive_known_id_num_bits_29_output_tmp_3f5e2_8.clone(),
        next_pc_id_col3,
    );
    let wg_v5 = eval.m31_sub(input_fp_col2, m31_2);
    let memory_address_to_id_value_tmp_3f5e2_10 = eval.mem_addr_to_id(wg_v5);
    let next_fp_id_col9 = memory_address_to_id_value_tmp_3f5e2_10;
    eval.set_col(9, next_fp_id_col9);
    let wg_v6 = eval.m31_sub(input_fp_col2, m31_2);
    eval.set_sub_input_word(8, wg_v6);
    eval.set_lookup_word(41, m31_1444891767);
    let wg_v7 = eval.m31_sub(input_fp_col2, m31_2);
    eval.set_lookup_word(42, wg_v7);
    eval.set_lookup_word(43, next_fp_id_col9);
    let memory_id_to_big_value_tmp_3f5e2_12 = eval.mem_id_to_value(next_fp_id_col9);
    let next_fp_limb_0_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_12.clone(), 0);
    eval.set_col(10, next_fp_limb_0_col10);
    let next_fp_limb_1_col11 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_12.clone(), 1);
    eval.set_col(11, next_fp_limb_1_col11);
    let next_fp_limb_2_col12 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_12.clone(), 2);
    eval.set_col(12, next_fp_limb_2_col12);
    let next_fp_limb_3_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_3f5e2_12.clone(), 3);
    eval.set_col(13, next_fp_limb_3_col13);
    let wg_v8 = eval.u16_from_m31(next_fp_limb_3_col13);
    let wg_v9 = eval.u16_and(wg_v8, 2);
    let partial_limb_msb_tmp_3f5e2_13 = eval.u16_shr(wg_v9, 1);
    let partial_limb_msb_col14 = eval.u16_as_m31(partial_limb_msb_tmp_3f5e2_13);
    eval.set_col(14, partial_limb_msb_col14);
    eval.set_sub_input_word(10, next_fp_id_col9);
    eval.set_lookup_word(44, m31_1662111297);
    eval.set_lookup_word(45, next_fp_id_col9);
    eval.set_lookup_word(46, next_fp_limb_0_col10);
    eval.set_lookup_word(47, next_fp_limb_1_col11);
    eval.set_lookup_word(48, next_fp_limb_2_col12);
    eval.set_lookup_word(49, next_fp_limb_3_col13);
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
    let read_positive_known_id_num_bits_29_output_tmp_3f5e2_15 = eval.felt_from_limbs([
        next_fp_limb_0_col10,
        next_fp_limb_1_col11,
        next_fp_limb_2_col12,
        next_fp_limb_3_col13,
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
    let read_positive_num_bits_29_output_tmp_3f5e2_16 = (
        read_positive_known_id_num_bits_29_output_tmp_3f5e2_15.clone(),
        next_fp_id_col9,
    );
    let enabler_col15 = eval.enabler();
    eval.set_col(15, enabler_col15);
    eval.set_lookup_word(74, m31_428564188);
    eval.set_lookup_word(75, input_pc_col0);
    eval.set_lookup_word(76, input_ap_col1);
    eval.set_lookup_word(77, input_fp_col2);
    eval.set_lookup_word(78, m31_428564188);
    let wg_v10 = eval.m31_mul(next_pc_limb_1_col5, m31_512);
    let wg_v11 = eval.m31_add(next_pc_limb_0_col4, wg_v10);
    let wg_v12 = eval.m31_mul(next_pc_limb_2_col6, m31_262144);
    let wg_v13 = eval.m31_add(wg_v11, wg_v12);
    let wg_v14 = eval.m31_mul(next_pc_limb_3_col7, m31_134217728);
    let wg_v15 = eval.m31_add(wg_v13, wg_v14);
    eval.set_lookup_word(79, wg_v15);
    eval.set_lookup_word(80, input_ap_col1);
    let wg_v16 = eval.m31_mul(next_fp_limb_1_col11, m31_512);
    let wg_v17 = eval.m31_add(next_fp_limb_0_col10, wg_v16);
    let wg_v18 = eval.m31_mul(next_fp_limb_2_col12, m31_262144);
    let wg_v19 = eval.m31_add(wg_v17, wg_v18);
    let wg_v20 = eval.m31_mul(next_fp_limb_3_col13, m31_134217728);
    let wg_v21 = eval.m31_add(wg_v19, wg_v20);
    eval.set_lookup_word(81, wg_v21);
    eval.set_lookup_word(82, m31_1);
    eval.set_lookup_word(83, enabler_col15);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `ret_opcode_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
            |(row_index, (row, lookup_data, sub_component_inputs, ret_opcode_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    ret_opcode_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                ret_opcode_row_body(&mut eval);
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
                *lookup_data.opcodes_5 = [lw[74], lw[75], lw[76], lw[77]];
                *lookup_data.opcodes_6 = [lw[78], lw[79], lw[80], lw[81]];
                *lookup_data.mults_0 = lw[82];
                *lookup_data.mults_1 = lw[83];
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
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) };
                *sub_component_inputs.memory_id_to_big[1] =
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) };
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

/// Record the `ret_opcode` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_ret_opcode() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("ret_opcode");
    ret_opcode_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    84;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    memory_address_to_id_3: 3,
    memory_id_to_big_4: 30,
    opcodes_5: 4,
    opcodes_6: 4,
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
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 9, 1),
    ("memory_id_to_big", 1, "memory_id_to_big_state", 0, 10, 1),
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
        "opcodes_5",
        "mults_1",
        false,
    ),
    ("opcodes_6", "mults_1", true, "", "", false),
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
        ld.opcodes_5.iter().flatten().copied().collect(),
        ld.opcodes_6.iter().flatten().copied().collect(),
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
        sci.memory_id_to_big[0]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.memory_id_to_big[1]
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
    opcodes_5: Vec<[PackedM31; 4]>,
    opcodes_6: Vec<[PackedM31; 4]>,
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
    opcodes_5: 4,
    opcodes_6: 4,
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
            &self.lookup_data.opcodes_5,
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
            &self.lookup_data.opcodes_6,
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

crate::jit_sub_accessors!(N_SUB_INPUT_WORDS, n_addr = 2, n_id = 2);
