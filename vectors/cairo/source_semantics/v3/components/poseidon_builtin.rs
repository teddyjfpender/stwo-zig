// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::poseidon_builtin::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{memory_address_to_id, poseidon_aggregator};
use crate::witness::prelude::*;

#[derive(Default)]
pub struct ClaimGenerator {
    pub log_size: u32,
    pub poseidon_builtin_segment_start: u32,
}

impl ClaimGenerator {
    pub fn new(log_size: u32, poseidon_builtin_segment_start: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            log_size,
            poseidon_builtin_segment_start,
        }
    }

    pub fn write_trace(
        self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        poseidon_aggregator_state: &poseidon_aggregator::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            log_size,
            self.poseidon_builtin_segment_start,
            memory_address_to_id_state,
            poseidon_aggregator_state,
        );
        for inputs in sub_component_inputs.memory_address_to_id {
            add_inputs(
                memory_address_to_id_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.poseidon_aggregator {
            add_inputs(
                poseidon_aggregator_state,
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 6],
    poseidon_aggregator: [Vec<poseidon_aggregator::PackedInputType>; 1],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    log_size: u32,
    poseidon_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    poseidon_aggregator_state: &poseidon_aggregator::ClaimGenerator,
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
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1551892206 = PackedM31::broadcast(M31::from(1551892206));
    let M31_2 = PackedM31::broadcast(M31::from(2));
    let M31_3 = PackedM31::broadcast(M31::from(3));
    let M31_4 = PackedM31::broadcast(M31::from(4));
    let M31_5 = PackedM31::broadcast(M31::from(5));
    let M31_6 = PackedM31::broadcast(M31::from(6));
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
            let instance_addr_tmp_a172e_0 = (((seq) * (M31_6))
                + (PackedM31::broadcast(M31::from(poseidon_builtin_segment_start))));

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_1 =
                memory_address_to_id_state.deduce_output(instance_addr_tmp_a172e_0);
            let input_state_0_id_col0 = memory_address_to_id_value_tmp_a172e_1;
            *row[0] = input_state_0_id_col0;
            *sub_component_inputs.memory_address_to_id[0] = instance_addr_tmp_a172e_0;
            *lookup_data.memory_address_to_id_0 = [
                M31_1444891767,
                instance_addr_tmp_a172e_0,
                input_state_0_id_col0,
            ];

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_3 =
                memory_address_to_id_state.deduce_output(((instance_addr_tmp_a172e_0) + (M31_1)));
            let input_state_1_id_col1 = memory_address_to_id_value_tmp_a172e_3;
            *row[1] = input_state_1_id_col1;
            *sub_component_inputs.memory_address_to_id[1] = ((instance_addr_tmp_a172e_0) + (M31_1));
            *lookup_data.memory_address_to_id_1 = [
                M31_1444891767,
                ((instance_addr_tmp_a172e_0) + (M31_1)),
                input_state_1_id_col1,
            ];

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_5 =
                memory_address_to_id_state.deduce_output(((instance_addr_tmp_a172e_0) + (M31_2)));
            let input_state_2_id_col2 = memory_address_to_id_value_tmp_a172e_5;
            *row[2] = input_state_2_id_col2;
            *sub_component_inputs.memory_address_to_id[2] = ((instance_addr_tmp_a172e_0) + (M31_2));
            *lookup_data.memory_address_to_id_2 = [
                M31_1444891767,
                ((instance_addr_tmp_a172e_0) + (M31_2)),
                input_state_2_id_col2,
            ];

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_7 =
                memory_address_to_id_state.deduce_output(((instance_addr_tmp_a172e_0) + (M31_3)));
            let output_state_0_id_col3 = memory_address_to_id_value_tmp_a172e_7;
            *row[3] = output_state_0_id_col3;
            *sub_component_inputs.memory_address_to_id[3] = ((instance_addr_tmp_a172e_0) + (M31_3));
            *lookup_data.memory_address_to_id_3 = [
                M31_1444891767,
                ((instance_addr_tmp_a172e_0) + (M31_3)),
                output_state_0_id_col3,
            ];

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_9 =
                memory_address_to_id_state.deduce_output(((instance_addr_tmp_a172e_0) + (M31_4)));
            let output_state_1_id_col4 = memory_address_to_id_value_tmp_a172e_9;
            *row[4] = output_state_1_id_col4;
            *sub_component_inputs.memory_address_to_id[4] = ((instance_addr_tmp_a172e_0) + (M31_4));
            *lookup_data.memory_address_to_id_4 = [
                M31_1444891767,
                ((instance_addr_tmp_a172e_0) + (M31_4)),
                output_state_1_id_col4,
            ];

            // Read Id.

            let memory_address_to_id_value_tmp_a172e_11 =
                memory_address_to_id_state.deduce_output(((instance_addr_tmp_a172e_0) + (M31_5)));
            let output_state_2_id_col5 = memory_address_to_id_value_tmp_a172e_11;
            *row[5] = output_state_2_id_col5;
            *sub_component_inputs.memory_address_to_id[5] = ((instance_addr_tmp_a172e_0) + (M31_5));
            *lookup_data.memory_address_to_id_5 = [
                M31_1444891767,
                ((instance_addr_tmp_a172e_0) + (M31_5)),
                output_state_2_id_col5,
            ];

            *sub_component_inputs.poseidon_aggregator[0] = (
                [
                    input_state_0_id_col0,
                    input_state_1_id_col1,
                    input_state_2_id_col2,
                ],
                [
                    output_state_0_id_col3,
                    output_state_1_id_col4,
                    output_state_2_id_col5,
                ],
            );
            *lookup_data.poseidon_aggregator_6 = [
                M31_1551892206,
                input_state_0_id_col0,
                input_state_1_id_col1,
                input_state_2_id_col2,
                output_state_0_id_col3,
                output_state_1_id_col4,
                output_state_2_id_col5,
            ];
            *lookup_data.mults_0 = M31_1;
        });

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `poseidon_builtin` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     memory_address_to_id_0[3] 0..2
//     memory_address_to_id_1[3] 3..5
//     memory_address_to_id_2[3] 6..8
//     memory_address_to_id_3[3] 9..11
//     memory_address_to_id_4[3] 12..14
//     memory_address_to_id_5[3] 15..17
//     poseidon_aggregator_6[7] 18..24
//     mults_0 25
//     (26 words)
//   SUB-INPUT words:
//     memory_address_to_id[0] 0
//     memory_address_to_id[1] 1
//     memory_address_to_id[2] 2
//     memory_address_to_id[3] 3
//     memory_address_to_id[4] 4
//     memory_address_to_id[5] 5
//     poseidon_aggregator[0] 6..11
//     (12 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 26;
pub(crate) const N_SUB_INPUT_WORDS: usize = 12;

/// The per-row `poseidon_builtin` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn poseidon_builtin_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_1 = eval.m31_const(1);
    let m31_2 = eval.m31_const(2);
    let m31_3 = eval.m31_const(3);
    let m31_4 = eval.m31_const(4);
    let m31_5 = eval.m31_const(5);
    let m31_6 = eval.m31_const(6);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1551892206 = eval.m31_const(1551892206);
    let seq = eval.iota();
    let wg_v0 = eval.m31_mul(seq, m31_6);
    let wg_v1 = eval.input(0);
    let instance_addr_tmp_a172e_0 = eval.m31_add(wg_v0, wg_v1);
    let memory_address_to_id_value_tmp_a172e_1 = eval.mem_addr_to_id(instance_addr_tmp_a172e_0);
    let input_state_0_id_col0 = memory_address_to_id_value_tmp_a172e_1;
    eval.set_col(0, input_state_0_id_col0);
    eval.set_sub_input_word(0, instance_addr_tmp_a172e_0);
    eval.set_lookup_word(0, m31_1444891767);
    eval.set_lookup_word(1, instance_addr_tmp_a172e_0);
    eval.set_lookup_word(2, input_state_0_id_col0);
    let wg_v2 = eval.m31_add(instance_addr_tmp_a172e_0, m31_1);
    let memory_address_to_id_value_tmp_a172e_3 = eval.mem_addr_to_id(wg_v2);
    let input_state_1_id_col1 = memory_address_to_id_value_tmp_a172e_3;
    eval.set_col(1, input_state_1_id_col1);
    let wg_v3 = eval.m31_add(instance_addr_tmp_a172e_0, m31_1);
    eval.set_sub_input_word(1, wg_v3);
    eval.set_lookup_word(3, m31_1444891767);
    let wg_v4 = eval.m31_add(instance_addr_tmp_a172e_0, m31_1);
    eval.set_lookup_word(4, wg_v4);
    eval.set_lookup_word(5, input_state_1_id_col1);
    let wg_v5 = eval.m31_add(instance_addr_tmp_a172e_0, m31_2);
    let memory_address_to_id_value_tmp_a172e_5 = eval.mem_addr_to_id(wg_v5);
    let input_state_2_id_col2 = memory_address_to_id_value_tmp_a172e_5;
    eval.set_col(2, input_state_2_id_col2);
    let wg_v6 = eval.m31_add(instance_addr_tmp_a172e_0, m31_2);
    eval.set_sub_input_word(2, wg_v6);
    eval.set_lookup_word(6, m31_1444891767);
    let wg_v7 = eval.m31_add(instance_addr_tmp_a172e_0, m31_2);
    eval.set_lookup_word(7, wg_v7);
    eval.set_lookup_word(8, input_state_2_id_col2);
    let wg_v8 = eval.m31_add(instance_addr_tmp_a172e_0, m31_3);
    let memory_address_to_id_value_tmp_a172e_7 = eval.mem_addr_to_id(wg_v8);
    let output_state_0_id_col3 = memory_address_to_id_value_tmp_a172e_7;
    eval.set_col(3, output_state_0_id_col3);
    let wg_v9 = eval.m31_add(instance_addr_tmp_a172e_0, m31_3);
    eval.set_sub_input_word(3, wg_v9);
    eval.set_lookup_word(9, m31_1444891767);
    let wg_v10 = eval.m31_add(instance_addr_tmp_a172e_0, m31_3);
    eval.set_lookup_word(10, wg_v10);
    eval.set_lookup_word(11, output_state_0_id_col3);
    let wg_v11 = eval.m31_add(instance_addr_tmp_a172e_0, m31_4);
    let memory_address_to_id_value_tmp_a172e_9 = eval.mem_addr_to_id(wg_v11);
    let output_state_1_id_col4 = memory_address_to_id_value_tmp_a172e_9;
    eval.set_col(4, output_state_1_id_col4);
    let wg_v12 = eval.m31_add(instance_addr_tmp_a172e_0, m31_4);
    eval.set_sub_input_word(4, wg_v12);
    eval.set_lookup_word(12, m31_1444891767);
    let wg_v13 = eval.m31_add(instance_addr_tmp_a172e_0, m31_4);
    eval.set_lookup_word(13, wg_v13);
    eval.set_lookup_word(14, output_state_1_id_col4);
    let wg_v14 = eval.m31_add(instance_addr_tmp_a172e_0, m31_5);
    let memory_address_to_id_value_tmp_a172e_11 = eval.mem_addr_to_id(wg_v14);
    let output_state_2_id_col5 = memory_address_to_id_value_tmp_a172e_11;
    eval.set_col(5, output_state_2_id_col5);
    let wg_v15 = eval.m31_add(instance_addr_tmp_a172e_0, m31_5);
    eval.set_sub_input_word(5, wg_v15);
    eval.set_lookup_word(15, m31_1444891767);
    let wg_v16 = eval.m31_add(instance_addr_tmp_a172e_0, m31_5);
    eval.set_lookup_word(16, wg_v16);
    eval.set_lookup_word(17, output_state_2_id_col5);
    eval.set_sub_input_word(6, input_state_0_id_col0);
    eval.set_sub_input_word(7, input_state_1_id_col1);
    eval.set_sub_input_word(8, input_state_2_id_col2);
    eval.set_sub_input_word(9, output_state_0_id_col3);
    eval.set_sub_input_word(10, output_state_1_id_col4);
    eval.set_sub_input_word(11, output_state_2_id_col5);
    eval.set_lookup_word(18, m31_1551892206);
    eval.set_lookup_word(19, input_state_0_id_col0);
    eval.set_lookup_word(20, input_state_1_id_col1);
    eval.set_lookup_word(21, input_state_2_id_col2);
    eval.set_lookup_word(22, output_state_0_id_col3);
    eval.set_lookup_word(23, output_state_1_id_col4);
    eval.set_lookup_word(24, output_state_2_id_col5);
    eval.set_lookup_word(25, m31_1);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `poseidon_builtin_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    log_size: u32,
    poseidon_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    poseidon_aggregator_state: &poseidon_aggregator::ClaimGenerator,
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
                None,
                vec![Simd::splat(poseidon_builtin_segment_start)],
                row_index,
                &enabler_col,
                N_LOOKUP_WORDS,
                N_SUB_INPUT_WORDS,
            );
            poseidon_builtin_row_body(&mut eval);
            let lw = eval.lookup_scratch();
            *lookup_data.memory_address_to_id_0 = [lw[0], lw[1], lw[2]];
            *lookup_data.memory_address_to_id_1 = [lw[3], lw[4], lw[5]];
            *lookup_data.memory_address_to_id_2 = [lw[6], lw[7], lw[8]];
            *lookup_data.memory_address_to_id_3 = [lw[9], lw[10], lw[11]];
            *lookup_data.memory_address_to_id_4 = [lw[12], lw[13], lw[14]];
            *lookup_data.memory_address_to_id_5 = [lw[15], lw[16], lw[17]];
            *lookup_data.poseidon_aggregator_6 =
                [lw[18], lw[19], lw[20], lw[21], lw[22], lw[23], lw[24]];
            *lookup_data.mults_0 = lw[25];
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
            *sub_component_inputs.memory_address_to_id[5] =
                unsafe { PackedM31::from_simd_unchecked(sw[5]) };
            *sub_component_inputs.poseidon_aggregator[0] = (
                [
                    unsafe { PackedM31::from_simd_unchecked(sw[6]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[7]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[8]) },
                ],
                [
                    unsafe { PackedM31::from_simd_unchecked(sw[9]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[10]) },
                    unsafe { PackedM31::from_simd_unchecked(sw[11]) },
                ],
            );
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
        poseidon_aggregator_state: &poseidon_aggregator::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            log_size,
            self.poseidon_builtin_segment_start,
            memory_address_to_id_state,
            poseidon_aggregator_state,
        );
        for inputs in sub_component_inputs.memory_address_to_id {
            add_inputs(
                memory_address_to_id_state,
                &inputs,
                inputs.len() * N_LANES,
                0,
            );
        }
        for inputs in sub_component_inputs.poseidon_aggregator {
            add_inputs(
                poseidon_aggregator_state,
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

/// Record the `poseidon_builtin` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_poseidon_builtin() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("poseidon_builtin", 1, Some(2));
    poseidon_builtin_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    26;
    memory_address_to_id_0: 3,
    memory_address_to_id_1: 3,
    memory_address_to_id_2: 3,
    memory_address_to_id_3: 3,
    memory_address_to_id_4: 3,
    memory_address_to_id_5: 3,
    poseidon_aggregator_6: 7,
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
    (
        "memory_address_to_id",
        5,
        "memory_address_to_id_state",
        0,
        5,
        1,
    ),
    (
        "poseidon_aggregator",
        0,
        "poseidon_aggregator_state",
        0,
        6,
        6,
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
        "memory_address_to_id_1",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_2",
        "mults_0",
        false,
        "memory_address_to_id_3",
        "mults_0",
        false,
    ),
    (
        "memory_address_to_id_4",
        "mults_0",
        false,
        "memory_address_to_id_5",
        "mults_0",
        false,
    ),
    ("poseidon_aggregator_6", "mults_0", false, "", "", false),
];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.memory_address_to_id_0
            .iter()
            .flatten()
            .copied()
            .collect(),
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
        ld.memory_address_to_id_3
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_4
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_address_to_id_5
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.poseidon_aggregator_6.iter().flatten().copied().collect(),
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
        sci.memory_address_to_id[5]
            .iter()
            .map(|v| v.into_simd())
            .collect::<Vec<_>>(),
        sci.poseidon_aggregator[0]
            .iter()
            .flat_map(|t| {
                vec![
                    t.0[0].into_simd(),
                    t.0[1].into_simd(),
                    t.0[2].into_simd(),
                    t.1[0].into_simd(),
                    t.1[1].into_simd(),
                    t.1[2].into_simd(),
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
    log_size: u32,
    poseidon_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    poseidon_aggregator_state: &poseidon_aggregator::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        log_size.clone(),
        poseidon_builtin_segment_start.clone(),
        memory_address_to_id_state,
        poseidon_aggregator_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        log_size,
        poseidon_builtin_segment_start,
        memory_address_to_id_state,
        poseidon_aggregator_state,
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
    memory_address_to_id_1: Vec<[PackedM31; 3]>,
    memory_address_to_id_2: Vec<[PackedM31; 3]>,
    memory_address_to_id_3: Vec<[PackedM31; 3]>,
    memory_address_to_id_4: Vec<[PackedM31; 3]>,
    memory_address_to_id_5: Vec<[PackedM31; 3]>,
    poseidon_aggregator_6: Vec<[PackedM31; 7]>,
    mults_0: Vec<PackedM31>,
}

pub struct InteractionClaimGenerator {
    log_size: u32,
    lookup_data: LookupData,
}
// === BEGIN relation_lookup_source_codegen ===
crate::relation_lookup_source! {
    memory_address_to_id_0: 3,
    memory_address_to_id_1: 3,
    memory_address_to_id_2: 3,
    memory_address_to_id_3: 3,
    memory_address_to_id_4: 3,
    memory_address_to_id_5: 3,
    poseidon_aggregator_6: 7,
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
            &self.lookup_data.memory_address_to_id_4,
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

        // Sum last logup term.
        let mut col_gen = logup_gen.new_col();
        (
            col_gen.par_iter_mut(),
            &self.lookup_data.poseidon_aggregator_6,
            self.lookup_data.mults_0,
        )
            .into_par_iter()
            .for_each(|(writer, values, mult)| {
                let denom = common_lookup_elements.combine(values);
                writer.write_frac((mult).into(), denom);
            });
        col_gen.finalize_col();

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
