// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::assert_eq_opcode::{Claim, InteractionClaim, N_TRACE_COLUMNS};
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
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_16 = PackedM31::broadcast(M31::from(16));
    let M31_1719106205 = PackedM31::broadcast(M31::from(1719106205));
    let M31_2147483646 = PackedM31::broadcast(M31::from(2147483646));
    let M31_256 = PackedM31::broadcast(M31::from(256));
    let M31_32 = PackedM31::broadcast(M31::from(32));
    let M31_32767 = PackedM31::broadcast(M31::from(32767));
    let M31_32768 = PackedM31::broadcast(M31::from(32768));
    let M31_428564188 = PackedM31::broadcast(M31::from(428564188));
    let M31_64 = PackedM31::broadcast(M31::from(64));
    let M31_8 = PackedM31::broadcast(M31::from(8));
    let UInt16_0 = PackedUInt16::broadcast(UInt16::from(0));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_11 = PackedUInt16::broadcast(UInt16::from(11));
    let UInt16_127 = PackedUInt16::broadcast(UInt16::from(127));
    let UInt16_13 = PackedUInt16::broadcast(UInt16::from(13));
    let UInt16_3 = PackedUInt16::broadcast(UInt16::from(3));
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
            |(row_index, (row, lookup_data, sub_component_inputs, assert_eq_opcode_input))| {
                let input_pc_col0 = assert_eq_opcode_input.pc;
                *row[0] = input_pc_col0;
                let input_ap_col1 = assert_eq_opcode_input.ap;
                *row[1] = input_ap_col1;
                let input_fp_col2 = assert_eq_opcode_input.fp;
                *row[2] = input_fp_col2;

                // Decode Instruction.

                let memory_address_to_id_value_tmp_36a9d_0 =
                    memory_address_to_id_state.deduce_output(input_pc_col0);
                let memory_id_to_big_value_tmp_36a9d_1 =
                    memory_id_to_big_state.deduce_output(memory_address_to_id_value_tmp_36a9d_0);
                let offset0_tmp_36a9d_2 =
                    ((PackedUInt16::from_m31(memory_id_to_big_value_tmp_36a9d_1.get_m31(0)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(1),
                        )) & (UInt16_127))
                            << (UInt16_9)));
                let offset0_col3 = offset0_tmp_36a9d_2.as_m31();
                *row[3] = offset0_col3;
                let offset2_tmp_36a9d_3 =
                    ((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_36a9d_1.get_m31(3)))
                        >> (UInt16_5))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(4),
                        )) << (UInt16_4)))
                        + (((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(5),
                        )) & (UInt16_7))
                            << (UInt16_13)));
                let offset2_col4 = offset2_tmp_36a9d_3.as_m31();
                *row[4] = offset2_col4;
                let dst_base_fp_tmp_36a9d_4 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_36a9d_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_0))
                        & (UInt16_1));
                let dst_base_fp_col5 = dst_base_fp_tmp_36a9d_4.as_m31();
                *row[5] = dst_base_fp_col5;
                let op1_base_fp_tmp_36a9d_5 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_36a9d_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_3))
                        & (UInt16_1));
                let op1_base_fp_col6 = op1_base_fp_tmp_36a9d_5.as_m31();
                *row[6] = op1_base_fp_col6;
                let ap_update_add_1_tmp_36a9d_6 =
                    (((((PackedUInt16::from_m31(memory_id_to_big_value_tmp_36a9d_1.get_m31(5)))
                        >> (UInt16_3))
                        + ((PackedUInt16::from_m31(
                            memory_id_to_big_value_tmp_36a9d_1.get_m31(6),
                        )) << (UInt16_6)))
                        >> (UInt16_11))
                        & (UInt16_1));
                let ap_update_add_1_col7 = ap_update_add_1_tmp_36a9d_6.as_m31();
                *row[7] = ap_update_add_1_col7;
                *sub_component_inputs.verify_instruction[0] = (
                    input_pc_col0,
                    [offset0_col3, M31_32767, offset2_col4],
                    [
                        (((((dst_base_fp_col5) * (M31_8)) + (M31_16))
                            + ((op1_base_fp_col6) * (M31_64)))
                            + (((M31_1) - (op1_base_fp_col6)) * (M31_128))),
                        (((ap_update_add_1_col7) * (M31_32)) + (M31_256)),
                    ],
                    M31_0,
                );
                *lookup_data.verify_instruction_0 = [
                    M31_1719106205,
                    input_pc_col0,
                    offset0_col3,
                    M31_32767,
                    offset2_col4,
                    (((((dst_base_fp_col5) * (M31_8)) + (M31_16))
                        + ((op1_base_fp_col6) * (M31_64)))
                        + (((M31_1) - (op1_base_fp_col6)) * (M31_128))),
                    (((ap_update_add_1_col7) * (M31_32)) + (M31_256)),
                    M31_0,
                ];
                let decode_instruction_135e3_output_tmp_36a9d_7 = (
                    [
                        ((offset0_col3) - (M31_32768)),
                        M31_2147483646,
                        ((offset2_col4) - (M31_32768)),
                    ],
                    [
                        dst_base_fp_col5,
                        M31_1,
                        M31_0,
                        op1_base_fp_col6,
                        ((M31_1) - (op1_base_fp_col6)),
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        M31_0,
                        ap_update_add_1_col7,
                        M31_0,
                        M31_0,
                        M31_1,
                    ],
                    M31_0,
                );

                let mem_dst_base_col8 = (((dst_base_fp_col5) * (input_fp_col2))
                    + (((M31_1) - (dst_base_fp_col5)) * (input_ap_col1)));
                *row[8] = mem_dst_base_col8;
                let mem1_base_col9 = (((op1_base_fp_col6) * (input_fp_col2))
                    + ((decode_instruction_135e3_output_tmp_36a9d_7.1[4]) * (input_ap_col1)));
                *row[9] = mem1_base_col9;

                // Mem Verify Equal.

                // Read Id.

                let memory_address_to_id_value_tmp_36a9d_8 = memory_address_to_id_state
                    .deduce_output(
                        ((mem_dst_base_col8) + (decode_instruction_135e3_output_tmp_36a9d_7.0[0])),
                    );
                let dst_id_col10 = memory_address_to_id_value_tmp_36a9d_8;
                *row[10] = dst_id_col10;
                *sub_component_inputs.memory_address_to_id[0] =
                    ((mem_dst_base_col8) + (decode_instruction_135e3_output_tmp_36a9d_7.0[0]));
                *lookup_data.memory_address_to_id_1 = [
                    M31_1444891767,
                    ((mem_dst_base_col8) + (decode_instruction_135e3_output_tmp_36a9d_7.0[0])),
                    dst_id_col10,
                ];

                *sub_component_inputs.memory_address_to_id[1] =
                    ((mem1_base_col9) + (decode_instruction_135e3_output_tmp_36a9d_7.0[2]));
                *lookup_data.memory_address_to_id_2 = [
                    M31_1444891767,
                    ((mem1_base_col9) + (decode_instruction_135e3_output_tmp_36a9d_7.0[2])),
                    dst_id_col10,
                ];

                let enabler_col11 = enabler_col.packed_at(row_index);
                *row[11] = enabler_col11;
                *lookup_data.opcodes_3 =
                    [M31_428564188, input_pc_col0, input_ap_col1, input_fp_col2];
                *lookup_data.opcodes_4 = [
                    M31_428564188,
                    ((input_pc_col0) + (M31_1)),
                    ((input_ap_col1) + (ap_update_add_1_col7)),
                    input_fp_col2,
                ];
                *lookup_data.mults_0 = M31_1;
                *lookup_data.mults_1 = enabler_col11;
            },
        );

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `assert_eq_opcode` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     verify_instruction_0[8] 0..7
//     memory_address_to_id_1[3] 8..10
//     memory_address_to_id_2[3] 11..13
//     opcodes_3[4] 14..17
//     opcodes_4[4] 18..21
//     mults_0 22
//     mults_1 23
//     (24 words)
//   SUB-INPUT words:
//     verify_instruction[0] 0..6
//     memory_address_to_id[0] 7
//     memory_address_to_id[1] 8
//     (9 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::{WitnessEval, SLOT_AP, SLOT_FP, SLOT_PC};

pub(crate) const N_LOOKUP_WORDS: usize = 24;
pub(crate) const N_SUB_INPUT_WORDS: usize = 9;

/// The per-row `assert_eq_opcode` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn assert_eq_opcode_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_8 = eval.m31_const(8);
    let m31_16 = eval.m31_const(16);
    let m31_32 = eval.m31_const(32);
    let m31_64 = eval.m31_const(64);
    let m31_128 = eval.m31_const(128);
    let m31_256 = eval.m31_const(256);
    let m31_32767 = eval.m31_const(32767);
    let m31_32768 = eval.m31_const(32768);
    let m31_428564188 = eval.m31_const(428564188);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1719106205 = eval.m31_const(1719106205);
    let m31_2147483646 = eval.m31_const(2147483646);
    let input_pc_col0 = eval.input(SLOT_PC);
    eval.set_col(0, input_pc_col0);
    let input_ap_col1 = eval.input(SLOT_AP);
    eval.set_col(1, input_ap_col1);
    let input_fp_col2 = eval.input(SLOT_FP);
    eval.set_col(2, input_fp_col2);
    let memory_address_to_id_value_tmp_36a9d_0 = eval.mem_addr_to_id(input_pc_col0);
    let memory_id_to_big_value_tmp_36a9d_1 =
        eval.mem_id_to_value(memory_address_to_id_value_tmp_36a9d_0);
    let wg_v0 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 0);
    let wg_v1 = eval.u16_from_m31(wg_v0);
    let wg_v2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 1);
    let wg_v3 = eval.u16_from_m31(wg_v2);
    let wg_v4 = eval.u16_and(wg_v3, 127);
    let wg_v5 = eval.u16_shl(wg_v4, 9);
    let offset0_tmp_36a9d_2 = eval.u16_add(wg_v1, wg_v5);
    let offset0_col3 = eval.u16_as_m31(offset0_tmp_36a9d_2);
    eval.set_col(3, offset0_col3);
    let wg_v6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 3);
    let wg_v7 = eval.u16_from_m31(wg_v6);
    let wg_v8 = eval.u16_shr(wg_v7, 5);
    let wg_v9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 4);
    let wg_v10 = eval.u16_from_m31(wg_v9);
    let wg_v11 = eval.u16_shl(wg_v10, 4);
    let wg_v12 = eval.u16_add(wg_v8, wg_v11);
    let wg_v13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 5);
    let wg_v14 = eval.u16_from_m31(wg_v13);
    let wg_v15 = eval.u16_and(wg_v14, 7);
    let wg_v16 = eval.u16_shl(wg_v15, 13);
    let offset2_tmp_36a9d_3 = eval.u16_add(wg_v12, wg_v16);
    let offset2_col4 = eval.u16_as_m31(offset2_tmp_36a9d_3);
    eval.set_col(4, offset2_col4);
    let wg_v17 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 5);
    let wg_v18 = eval.u16_from_m31(wg_v17);
    let wg_v19 = eval.u16_shr(wg_v18, 3);
    let wg_v20 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 6);
    let wg_v21 = eval.u16_from_m31(wg_v20);
    let wg_v22 = eval.u16_shl(wg_v21, 6);
    let wg_v23 = eval.u16_add(wg_v19, wg_v22);
    let wg_v24 = eval.u16_shr(wg_v23, 0);
    let dst_base_fp_tmp_36a9d_4 = eval.u16_and(wg_v24, 1);
    let dst_base_fp_col5 = eval.u16_as_m31(dst_base_fp_tmp_36a9d_4);
    eval.set_col(5, dst_base_fp_col5);
    let wg_v25 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 5);
    let wg_v26 = eval.u16_from_m31(wg_v25);
    let wg_v27 = eval.u16_shr(wg_v26, 3);
    let wg_v28 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 6);
    let wg_v29 = eval.u16_from_m31(wg_v28);
    let wg_v30 = eval.u16_shl(wg_v29, 6);
    let wg_v31 = eval.u16_add(wg_v27, wg_v30);
    let wg_v32 = eval.u16_shr(wg_v31, 3);
    let op1_base_fp_tmp_36a9d_5 = eval.u16_and(wg_v32, 1);
    let op1_base_fp_col6 = eval.u16_as_m31(op1_base_fp_tmp_36a9d_5);
    eval.set_col(6, op1_base_fp_col6);
    let wg_v33 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 5);
    let wg_v34 = eval.u16_from_m31(wg_v33);
    let wg_v35 = eval.u16_shr(wg_v34, 3);
    let wg_v36 = eval.felt_get_m31(&memory_id_to_big_value_tmp_36a9d_1.clone(), 6);
    let wg_v37 = eval.u16_from_m31(wg_v36);
    let wg_v38 = eval.u16_shl(wg_v37, 6);
    let wg_v39 = eval.u16_add(wg_v35, wg_v38);
    let wg_v40 = eval.u16_shr(wg_v39, 11);
    let ap_update_add_1_tmp_36a9d_6 = eval.u16_and(wg_v40, 1);
    let ap_update_add_1_col7 = eval.u16_as_m31(ap_update_add_1_tmp_36a9d_6);
    eval.set_col(7, ap_update_add_1_col7);
    let wg_v41 = eval.m31_mul(dst_base_fp_col5, m31_8);
    let wg_v42 = eval.m31_add(wg_v41, m31_16);
    let wg_v43 = eval.m31_mul(op1_base_fp_col6, m31_64);
    let wg_v44 = eval.m31_add(wg_v42, wg_v43);
    let wg_v45 = eval.m31_sub(m31_1, op1_base_fp_col6);
    let wg_v46 = eval.m31_mul(wg_v45, m31_128);
    let wg_v47 = eval.m31_add(wg_v44, wg_v46);
    let wg_v48 = eval.m31_mul(ap_update_add_1_col7, m31_32);
    let wg_v49 = eval.m31_add(wg_v48, m31_256);
    eval.set_sub_input_word(0, input_pc_col0);
    eval.set_sub_input_word(1, offset0_col3);
    eval.set_sub_input_word(2, m31_32767);
    eval.set_sub_input_word(3, offset2_col4);
    eval.set_sub_input_word(4, wg_v47);
    eval.set_sub_input_word(5, wg_v49);
    eval.set_sub_input_word(6, m31_0);
    eval.set_lookup_word(0, m31_1719106205);
    eval.set_lookup_word(1, input_pc_col0);
    eval.set_lookup_word(2, offset0_col3);
    eval.set_lookup_word(3, m31_32767);
    eval.set_lookup_word(4, offset2_col4);
    let wg_v50 = eval.m31_mul(dst_base_fp_col5, m31_8);
    let wg_v51 = eval.m31_add(wg_v50, m31_16);
    let wg_v52 = eval.m31_mul(op1_base_fp_col6, m31_64);
    let wg_v53 = eval.m31_add(wg_v51, wg_v52);
    let wg_v54 = eval.m31_sub(m31_1, op1_base_fp_col6);
    let wg_v55 = eval.m31_mul(wg_v54, m31_128);
    let wg_v56 = eval.m31_add(wg_v53, wg_v55);
    eval.set_lookup_word(5, wg_v56);
    let wg_v57 = eval.m31_mul(ap_update_add_1_col7, m31_32);
    let wg_v58 = eval.m31_add(wg_v57, m31_256);
    eval.set_lookup_word(6, wg_v58);
    eval.set_lookup_word(7, m31_0);
    let wg_v59 = eval.m31_sub(offset0_col3, m31_32768);
    let wg_v60 = eval.m31_sub(offset2_col4, m31_32768);
    let wg_v61 = eval.m31_sub(m31_1, op1_base_fp_col6);
    let decode_instruction_135e3_output_tmp_36a9d_7 = (
        [wg_v59, m31_2147483646, wg_v60],
        [
            dst_base_fp_col5,
            m31_1,
            m31_0,
            op1_base_fp_col6,
            wg_v61,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            m31_0,
            ap_update_add_1_col7,
            m31_0,
            m31_0,
            m31_1,
        ],
        m31_0,
    );
    let wg_v62 = eval.m31_mul(dst_base_fp_col5, input_fp_col2);
    let wg_v63 = eval.m31_sub(m31_1, dst_base_fp_col5);
    let wg_v64 = eval.m31_mul(wg_v63, input_ap_col1);
    let mem_dst_base_col8 = eval.m31_add(wg_v62, wg_v64);
    eval.set_col(8, mem_dst_base_col8);
    let wg_v65 = eval.m31_mul(op1_base_fp_col6, input_fp_col2);
    let wg_v66 = eval.m31_mul(
        decode_instruction_135e3_output_tmp_36a9d_7.1[4],
        input_ap_col1,
    );
    let mem1_base_col9 = eval.m31_add(wg_v65, wg_v66);
    eval.set_col(9, mem1_base_col9);
    let wg_v67 = eval.m31_add(
        mem_dst_base_col8,
        decode_instruction_135e3_output_tmp_36a9d_7.0[0],
    );
    let memory_address_to_id_value_tmp_36a9d_8 = eval.mem_addr_to_id(wg_v67);
    let dst_id_col10 = memory_address_to_id_value_tmp_36a9d_8;
    eval.set_col(10, dst_id_col10);
    let wg_v68 = eval.m31_add(
        mem_dst_base_col8,
        decode_instruction_135e3_output_tmp_36a9d_7.0[0],
    );
    eval.set_sub_input_word(7, wg_v68);
    eval.set_lookup_word(8, m31_1444891767);
    let wg_v69 = eval.m31_add(
        mem_dst_base_col8,
        decode_instruction_135e3_output_tmp_36a9d_7.0[0],
    );
    eval.set_lookup_word(9, wg_v69);
    eval.set_lookup_word(10, dst_id_col10);
    let wg_v70 = eval.m31_add(
        mem1_base_col9,
        decode_instruction_135e3_output_tmp_36a9d_7.0[2],
    );
    eval.set_sub_input_word(8, wg_v70);
    eval.set_lookup_word(11, m31_1444891767);
    let wg_v71 = eval.m31_add(
        mem1_base_col9,
        decode_instruction_135e3_output_tmp_36a9d_7.0[2],
    );
    eval.set_lookup_word(12, wg_v71);
    eval.set_lookup_word(13, dst_id_col10);
    let enabler_col11 = eval.enabler();
    eval.set_col(11, enabler_col11);
    eval.set_lookup_word(14, m31_428564188);
    eval.set_lookup_word(15, input_pc_col0);
    eval.set_lookup_word(16, input_ap_col1);
    eval.set_lookup_word(17, input_fp_col2);
    eval.set_lookup_word(18, m31_428564188);
    let wg_v72 = eval.m31_add(input_pc_col0, m31_1);
    eval.set_lookup_word(19, wg_v72);
    let wg_v73 = eval.m31_add(input_ap_col1, ap_update_add_1_col7);
    eval.set_lookup_word(20, wg_v73);
    eval.set_lookup_word(21, input_fp_col2);
    eval.set_lookup_word(22, m31_1);
    eval.set_lookup_word(23, enabler_col11);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `assert_eq_opcode_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
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
            |(row_index, (row, lookup_data, sub_component_inputs, assert_eq_opcode_input))| {
                let mut eval = SimdWitnessEval::new(
                    row,
                    memory_address_to_id_state,
                    memory_id_to_big_state,
                    assert_eq_opcode_input,
                    row_index,
                    &enabler_col,
                    N_LOOKUP_WORDS,
                    N_SUB_INPUT_WORDS,
                );
                assert_eq_opcode_row_body(&mut eval);
                let lw = eval.lookup_scratch();
                *lookup_data.verify_instruction_0 =
                    [lw[0], lw[1], lw[2], lw[3], lw[4], lw[5], lw[6], lw[7]];
                *lookup_data.memory_address_to_id_1 = [lw[8], lw[9], lw[10]];
                *lookup_data.memory_address_to_id_2 = [lw[11], lw[12], lw[13]];
                *lookup_data.opcodes_3 = [lw[14], lw[15], lw[16], lw[17]];
                *lookup_data.opcodes_4 = [lw[18], lw[19], lw[20], lw[21]];
                *lookup_data.mults_0 = lw[22];
                *lookup_data.mults_1 = lw[23];
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

/// Record the `assert_eq_opcode` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_assert_eq_opcode() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::new("assert_eq_opcode");
    assert_eq_opcode_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    24;
    verify_instruction_0: 8,
    memory_address_to_id_1: 3,
    memory_address_to_id_2: 3,
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
    (
        "memory_address_to_id",
        1,
        "memory_address_to_id_state",
        0,
        8,
        1,
    ),
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
        "memory_address_to_id_2",
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
        ld.memory_address_to_id_2
            .iter()
            .flatten()
            .copied()
            .collect(),
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
        sci.memory_address_to_id[1]
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
    memory_address_to_id_2: Vec<[PackedM31; 3]>,
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
    memory_address_to_id_2: 3,
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
            &self.lookup_data.memory_address_to_id_2,
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

crate::jit_sub_accessors!(N_SUB_INPUT_WORDS, n_addr = 2, n_id = 0);
