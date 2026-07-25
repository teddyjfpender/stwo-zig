// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::jump_opcode_rel_imm::{Claim, InteractionClaim, N_TRACE_COLUMNS};
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 1],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 1],
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
    let M31_134217728 = PackedM31::broadcast(M31::from(134217728));
    let M31_136 = PackedM31::broadcast(M31::from(136));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2147483646 = PackedM31::broadcast(M31::from(2147483646));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_262144 = PackedM31::broadcast(M31::from(262144));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32767 = PackedM31::broadcast(M31::from(32767));
    let M31_32769 = PackedM31::broadcast(M31::from(32769));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_508 = PackedM31::broadcast(M31::from(508));
    let M31_511 = PackedM31::broadcast(M31::from(511));
    let M31_512 = PackedM31::broadcast(M31::from(512));
    let M31_536870912 = PackedM31::broadcast(M31::from(536870912));
    let M31_56 = PackedM31::broadcast(M31::from(56));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
    let UInt16_6 = PackedUInt16::broadcast(UInt16::from(6));
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
            |(row_index, (row, lookup_data, sub_component_inputs, jump_opcode_rel_imm_input))| {
                let input_pc_col0 = jump_opcode_rel_imm_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = jump_opcode_rel_imm_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = jump_opcode_rel_imm_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_78364_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_78364_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_78364_0);
                let ap_update_add_1_tmp_78364_2 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_78364_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_78364_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col3 = ap_update_add_1_tmp_78364_2.as_m31();
                *row[3] = ap_update_add_1_col3;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [M31_32767, M31_32767, M31_32769],
                    [M31_56, ((M31_4) + ((ap_update_add_1_col3) * (M31_32)))],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    M31_32767,
                    M31_32767,
                    M31_32769,
                    M31_56,
                    ((M31_4) + ((ap_update_add_1_col3) * (M31_32))),
                    M31_0,
                ];
                let decode_instruction_7dcb2_output_tmp_78364_3 = (
                    [M31_2147483646, M31_2147483646, M31_1],
                    [
                        M31_1,
                        M31_1,
                        M31_1,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_1,
                        M31_0,
                        M31_0,
                        ap_update_add_1_col3,
                        M31_0,
                        M31_0,
                        M31_0,
                    ],
                    M31_0,
                );

                // Read Small.

                // Read Id.

                let memory_address_to_id_value_tmp_78364_4 =
                    memory_address_to_id_state.deduce_output(((input_pc_col0) + (M31_1)));
                let next_pc_id_col4 = memory_address_to_id_value_tmp_78364_4;
                *row[4] = next_pc_id_col4;
                *sub_component_inputs.memory_address_to_id[0] = ((input_pc_col0) + (M31_1));
                *lookup_data.memory_address_to_id_1 =
                    [M31_1444891767, ((input_pc_col0) + (M31_1)), next_pc_id_col4];

                let memory_id_to_big_value_tmp_78364_6 =
                    memory_id_to_big_state.deduce_output(next_pc_id_col4);

                // Decode Small Sign.

                let msb_tmp_78364_7 = memory_id_to_big_value_tmp_78364_6.get_m31(27).eq(M31_256);
                let msb_col5 = msb_tmp_78364_7.as_m31();
                *row[5] = msb_col5;
                let mid_limbs_set_tmp_78364_8 =
                    ((memory_id_to_big_value_tmp_78364_6.get_m31(20).eq(M31_511))
                        & (msb_tmp_78364_7));
                let mid_limbs_set_col6 = mid_limbs_set_tmp_78364_8.as_m31();
                *row[6] = mid_limbs_set_col6;
                let decode_small_sign_output_tmp_78364_9 = [
                    msb_col5,
                    mid_limbs_set_col6,
                    ((mid_limbs_set_col6) * (M31_508)),
                    ((mid_limbs_set_col6) * (M31_511)),
                    (((msb_col5) * (M31_136)) - (mid_limbs_set_col6)),
                    ((msb_col5) * (M31_256)),
                ];

                let next_pc_limb_0_col7 = memory_id_to_big_value_tmp_78364_6.get_m31(0);
                *row[7] = next_pc_limb_0_col7;
                let next_pc_limb_1_col8 = memory_id_to_big_value_tmp_78364_6.get_m31(1);
                *row[8] = next_pc_limb_1_col8;
                let next_pc_limb_2_col9 = memory_id_to_big_value_tmp_78364_6.get_m31(2);
                *row[9] = next_pc_limb_2_col9;
                let remainder_bits_tmp_78364_10 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_78364_6.get_m31(3)))
                        & (UInt16_3));
                let remainder_bits_col10 = remainder_bits_tmp_78364_10.as_m31();
                *row[10] = remainder_bits_col10;

                // Cond Range Check 2.

                let partial_limb_msb_tmp_78364_11 =
                    (((PackedUInt16::from_m31(remainder_bits_col10)) & (UInt16_2)) >> (UInt16_1));
                let partial_limb_msb_col11 = partial_limb_msb_tmp_78364_11.as_m31();
                *row[11] = partial_limb_msb_col11;

                *sub_component_inputs.memory_id_to_big[0] = next_pc_id_col4;
                *lookup_data.memory_id_to_big_2 = [
                    M31_1662111297,
                    next_pc_id_col4,
                    next_pc_limb_0_col7,
                    next_pc_limb_1_col8,
                    next_pc_limb_2_col9,
                    ((remainder_bits_col10) + (decode_small_sign_output_tmp_78364_9[2])),
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[3],
                    decode_small_sign_output_tmp_78364_9[4],
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    M31_0,
                    decode_small_sign_output_tmp_78364_9[5],
                ];
                let read_small_output_tmp_78364_13 = (
                    ((((((next_pc_limb_0_col7) + ((next_pc_limb_1_col8) * (M31_512)))
                        + ((next_pc_limb_2_col9) * (M31_262144)))
                        + ((remainder_bits_col10) * (M31_134217728)))
                        - (msb_col5))
                        - ((M31_536870912) * (mid_limbs_set_col6))),
                    next_pc_id_col4,
                );

                let enabler_col12 = enabler_col.packed_at(row_index);
                *row[12] = enabler_col12;
                *lookup_data.opcodes_3 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_4 = [
                    M31_428564188,
                    ((input_pc_col0) + (read_small_output_tmp_78364_13.0)),
                    ((input_ap_col1) + (ap_update_add_1_col3)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col12;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `jump_opcode_rel_imm` — mechanical rewrite of
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
//     opcodes_3[4] 41..44
//     opcodes_4[4] 45..48
//     mults_0 49
//     mults_1 50
//     (51 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_id_to_big[0] 8
//     (9 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 51;
pub(crate) const N_SUB_INPUT_WORDS: usize = 9;

/// The per-row `jump_opcode_rel_imm` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn jump_opcode_rel_imm_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_4 = eval.m31_const(4);
    let m31_32 = eval.m31_const(32);
    let m31_56 = eval.m31_const(56);
    let m31_136 = eval.m31_const(136);
    let m31_256 = eval.m31_const(256);
    let m31_508 = eval.m31_const(508);
    let m31_511 = eval.m31_const(511);
    let m31_512 = eval.m31_const(512);
    let m31_32767 = eval.m31_const(32767);
    let m31_32769 = eval.m31_const(32769);
    let m31_262144 = eval.m31_const(262144);
    let m31_134217728 = eval.m31_const(134217728);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_536870912 = eval.m31_const(536870912);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let m31_1719106205 = eval.m31_const(1719106205);
    let m31_2147483646 = eval.m31_const(2147483646);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_78364_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_78364_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_78364_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_1.clone(), 5);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.u16_shr(wg_v1, 3);
    let wg_v3 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_1.clone(), 6);
    let wg_v4 = eval.u16_from_m31(wg_v3);
    let wg_v5 = eval.u16_shl(wg_v4, 6);
    let wg_v6 = eval.u16_add(wg_v2, wg_v5);
    let wg_v7 = eval.u16_shr(wg_v6, 11);
    let ap_update_add_1_tmp_78364_2 = eval.u16_and(wg_v7, 1);
    let ap_update_add_1_col3 = eval.u16_as_m31(ap_update_add_1_tmp_78364_2);
    eval.set_col(3, ap_update_add_1_col3);
    let wg_v8 = eval.m31_mul(ap_update_add_1_col3, m31_32);
    let wg_v9 = eval.m31_add(m31_4, wg_v8);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, m31_32767);
    eval.set_sub_input_word(2, m31_32767);
    eval.set_sub_input_word(3, m31_32769);
    eval.set_sub_input_word(4, m31_56);
    eval.set_sub_input_word(5, wg_v9);
    eval.set_sub_input_word(6, m31_0);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, m31_32767);
    eval.set_lookup_word(3, m31_32767);
    eval.set_lookup_word(4, m31_32769);
    eval.set_lookup_word(5, m31_56);
    let wg_v10 = eval.m31_mul(ap_update_add_1_col3, m31_32);
    let wg_v11 = eval.m31_add(m31_4, wg_v10);
    eval.set_lookup_word(6, wg_v11);
    eval.set_lookup_word(7, m31_0);
    let decode_instruction_7dcb2_output_tmp_78364_3 = (
        [m31_2147483646, m31_2147483646, m31_1],
        [
            m31_1,
            m31_1,
            m31_1,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_1,
            m31_0,
            m31_0,
            ap_update_add_1_col3,
            m31_0,
            m31_0,
            m31_0,
        ],
        m31_0,
    );
    let wg_v12 = eval.m31_add(input_pc_col0, m31_1);
    let memory_address_to_id_value_tmp_78364_4 = eval.mem_addr_to_id(wg_v12);
    let next_pc_id_col4 = memory_address_to_id_value_tmp_78364_4;
    eval.set_col(4, next_pc_id_col4);
    let wg_v13 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_sub_input_word(7, wg_v13);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v14 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_lookup_word(9, wg_v14);
    eval.set_lookup_word(10, next_pc_id_col4);
    let memory_id_to_big_value_tmp_78364_6 = eval.mem_id_to_value(next_pc_id_col4);
    let wg_v15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 27);
    let msb_tmp_78364_7 = eval.m31_eq(wg_v15, m31_256);
    let msb_col5 = eval.mask_as_m31(msb_tmp_78364_7);
    eval.set_col(5, msb_col5);
    let wg_v16 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 20);
    let wg_v17 = eval.m31_eq(wg_v16, m31_511);
    let mid_limbs_set_tmp_78364_8 = eval.mask_and(wg_v17, msb_tmp_78364_7);
    let mid_limbs_set_col6 = eval.mask_as_m31(mid_limbs_set_tmp_78364_8);
    eval.set_col(6, mid_limbs_set_col6);
    let wg_v18 = eval.m31_mul(mid_limbs_set_col6, m31_508);
    let wg_v19 = eval.m31_mul(mid_limbs_set_col6, m31_511);
    let wg_v20 = eval.m31_mul(msb_col5, m31_136);
    let wg_v21 = eval.m31_sub(wg_v20, mid_limbs_set_col6);
    let wg_v22 = eval.m31_mul(msb_col5, m31_256);
    let decode_small_sign_output_tmp_78364_9 =
        [msb_col5, mid_limbs_set_col6, wg_v18, wg_v19, wg_v21, wg_v22];
    let next_pc_limb_0_col7 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 0);
    eval.set_col(7, next_pc_limb_0_col7);
    let next_pc_limb_1_col8 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 1);
    eval.set_col(8, next_pc_limb_1_col8);
    let next_pc_limb_2_col9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 2);
    eval.set_col(9, next_pc_limb_2_col9);
    let wg_v23 = eval.felt_get_m31(&memory_id_to_big_value_tmp_78364_6.clone(), 3);
    let wg_v24 = eval.u16_from_m31(wg_v23);
    let remainder_bits_tmp_78364_10 = eval.u16_and(wg_v24, 3);
    let remainder_bits_col10 = eval.u16_as_m31(remainder_bits_tmp_78364_10);
    eval.set_col(10, remainder_bits_col10);
    let wg_v25 = eval.u16_from_m31(remainder_bits_col10);
    let wg_v26 = eval.u16_and(wg_v25, 2);
    let partial_limb_msb_tmp_78364_11 = eval.u16_shr(wg_v26, 1);
    let partial_limb_msb_col11 = eval.u16_as_m31(partial_limb_msb_tmp_78364_11);
    eval.set_col(11, partial_limb_msb_col11);
    eval.set_sub_input_word(8, next_pc_id_col4);
    eval.set_lookup_word(11, m31_1662111297);
    eval.set_lookup_word(12, next_pc_id_col4);
    eval.set_lookup_word(13, next_pc_limb_0_col7);
    eval.set_lookup_word(14, next_pc_limb_1_col8);
    eval.set_lookup_word(15, next_pc_limb_2_col9);
    let wg_v27 = eval.m31_add(
        remainder_bits_col10,
        decode_small_sign_output_tmp_78364_9[2],
    );
    eval.set_lookup_word(16, wg_v27);
    eval.set_lookup_word(17, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(18, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(19, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(20, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(21, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(22, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(23, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(24, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(25, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(26, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(27, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(28, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(29, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(30, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(31, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(32, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(33, decode_small_sign_output_tmp_78364_9[3]);
    eval.set_lookup_word(34, decode_small_sign_output_tmp_78364_9[4]);
    eval.set_lookup_word(35, m31_0);
    eval.set_lookup_word(36, m31_0);
    eval.set_lookup_word(37, m31_0);
    eval.set_lookup_word(38, m31_0);
    eval.set_lookup_word(39, m31_0);
    eval.set_lookup_word(40, decode_small_sign_output_tmp_78364_9[5]);
    let wg_v28 = eval.m31_mul(next_pc_limb_1_col8, m31_512);
    let wg_v29 = eval.m31_add(next_pc_limb_0_col7, wg_v28);
    let wg_v30 = eval.m31_mul(next_pc_limb_2_col9, m31_262144);
    let wg_v31 = eval.m31_add(wg_v29, wg_v30);
    let wg_v32 = eval.m31_mul(remainder_bits_col10, m31_134217728);
    let wg_v33 = eval.m31_add(wg_v31, wg_v32);
    let wg_v34 = eval.m31_sub(wg_v33, msb_col5);
    let wg_v35 = eval.m31_mul(m31_536870912, mid_limbs_set_col6);
    let wg_v36 = eval.m31_sub(wg_v34, wg_v35);
    let read_small_output_tmp_78364_13 = (wg_v36, next_pc_id_col4);
    let enabler_col12 = eval.enabler();
    eval.set_col(12, enabler_col12);
    eval.set_lookup_word(41, m31_428564188);
    eval.set_lookup_word(42, input_pc_col0);
    eval.set_lookup_word(43, input_ap_col1);
    eval.set_lookup_word(44, input_fp_col2);
    eval.set_lookup_word(45, m31_428564188);
    let wg_v37 = eval.m31_add(input_pc_col0, read_small_output_tmp_78364_13.0);
    eval.set_lookup_word(46, wg_v37);
    let wg_v38 = eval.m31_add(input_ap_col1, ap_update_add_1_col3);
    eval.set_lookup_word(47, wg_v38);
    eval.set_lookup_word(48, input_fp_col2);
    eval.set_lookup_word(49, m31_1);
    eval.set_lookup_word(50, enabler_col12);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `jump_opcode_rel_imm_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
            |(row_index, (row, lookup_data, sub_component_inputs, jump_opcode_rel_imm_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    jump_opcode_rel_imm_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                jump_opcode_rel_imm_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.verify_instruction_0 =
                    [lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7]];
                *lookup_data.memory_address_to_id_1 = [lw[8], lw[9], lw[10]];
                *lookup_data.memory_id_to_big_2 = [
                    lw[11], lw[12], lw[13], lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20],
                    lw[21], lw[22], lw[23], lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30],
                    lw[31], lw[32], lw[33], lw[34], lw[35], lw[36], lw[37], lw[38], lw[39], lw[40],
                ];
                *lookup_data.opcodes_3 = [lw[41], lw[42], lw[43], lw[44]];
                *lookup_data.opcodes_4 = [lw[45], lw[46], lw[47], lw[48]];
                *lookup_data.mults_0 = lw[49];
                *lookup_data.mults_1 = lw[50];
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
                *sub_component_inputs.memory_id_to_big[0] =
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) };
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

/// Record the `jump_opcode_rel_imm` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_jump_opcode_rel_imm() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("jump_opcode_rel_imm");
    jump_opcode_rel_imm_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    51;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_id_to_big_2: 30,
    opcodes_3: 4,
    opcodes_4: 4,
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
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 8, 1),
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
        "opcodes_3",
        "mults_1",
        false,
    ),
    ("opcodes_4", "mults_1", true, "", "", false),
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
        ld.opcodes_3.iter().flatten().copied().collect(),
        ld.opcodes_4.iter().flatten().copied().collect(),
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
    opcodes_3: Vec<[PackedM31; 4]>,
    opcodes_4: Vec<[PackedM31; 4]>,
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
    opcodes_3: 4,
    opcodes_4: 4,
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
            &self.lookup_data.opcodes_3,
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
            &self.lookup_data.opcodes_4,
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

crate::jit_sub_accessors!(N_SUB_INPUT_WORDS, n_addr = 1, n_id = 1);
