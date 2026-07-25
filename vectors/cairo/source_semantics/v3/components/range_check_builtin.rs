// This file was created by the AIR team.

#![allow(unused_parens)]
use cairo_air::components::range_check_builtin::{Claim, InteractionClaim, N_TRACE_COLUMNS};
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{RawLogupTrace, RawLogupTraceGenerator};

use crate::witness::components::{memory_address_to_id, memory_id_to_big};
use crate::witness::prelude::*;

#[derive(Default)]
pub struct ClaimGenerator {
    pub log_size: u32,
    pub range_check_builtin_segment_start: u32,
}

impl ClaimGenerator {
    pub fn new(log_size: u32, range_check_builtin_segment_start: u32) -> Self {
        assert!(log_size >= LOG_N_LANES);
        Self {
            log_size,
            range_check_builtin_segment_start,
        }
    }

    pub fn write_trace(
        self,
        memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
        memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;

        let (trace, lookup_data, sub_component_inputs) = write_trace_simd(
            log_size,
            self.range_check_builtin_segment_start,
            memory_address_to_id_state,
            memory_id_to_big_state,
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
    memory_address_to_id: [Vec<memory_address_to_id::PackedInputType>; 1],
    memory_id_to_big: [Vec<memory_id_to_big::PackedInputType>; 1],
}

#[allow(clippy::useless_conversion)]
#[allow(unused_variables)]
#[allow(clippy::double_parens)]
#[allow(non_snake_case)]
fn write_trace_simd(
    log_size: u32,
    range_check_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
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

    let M31_0 = PackedM31::broadcast(M31::from(0));
    let M31_1 = PackedM31::broadcast(M31::from(1));
    let M31_1444891767 = PackedM31::broadcast(M31::from(1444891767));
    let M31_1662111297 = PackedM31::broadcast(M31::from(1662111297));
    let UInt16_1 = PackedUInt16::broadcast(UInt16::from(1));
    let UInt16_2 = PackedUInt16::broadcast(UInt16::from(2));
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

            // Read Positive Num Bits 128.

            // Read Id.

            let memory_address_to_id_value_tmp_e86ad_0 = memory_address_to_id_state.deduce_output(
                ((PackedM31::broadcast(M31::from(range_check_builtin_segment_start))) + (seq)),
            );
            let value_id_col0 = memory_address_to_id_value_tmp_e86ad_0;
            *row[0] = value_id_col0;
            *sub_component_inputs.memory_address_to_id[0] =
                ((PackedM31::broadcast(M31::from(range_check_builtin_segment_start))) + (seq));
            *lookup_data.memory_address_to_id_0 = [
                M31_1444891767,
                ((PackedM31::broadcast(M31::from(range_check_builtin_segment_start))) + (seq)),
                value_id_col0,
            ];

            // Read Positive Known Id Num Bits 128.

            let memory_id_to_big_value_tmp_e86ad_2 =
                memory_id_to_big_state.deduce_output(value_id_col0);
            let value_limb_0_col1 = memory_id_to_big_value_tmp_e86ad_2.get_m31(0);
            *row[1] = value_limb_0_col1;
            let value_limb_1_col2 = memory_id_to_big_value_tmp_e86ad_2.get_m31(1);
            *row[2] = value_limb_1_col2;
            let value_limb_2_col3 = memory_id_to_big_value_tmp_e86ad_2.get_m31(2);
            *row[3] = value_limb_2_col3;
            let value_limb_3_col4 = memory_id_to_big_value_tmp_e86ad_2.get_m31(3);
            *row[4] = value_limb_3_col4;
            let value_limb_4_col5 = memory_id_to_big_value_tmp_e86ad_2.get_m31(4);
            *row[5] = value_limb_4_col5;
            let value_limb_5_col6 = memory_id_to_big_value_tmp_e86ad_2.get_m31(5);
            *row[6] = value_limb_5_col6;
            let value_limb_6_col7 = memory_id_to_big_value_tmp_e86ad_2.get_m31(6);
            *row[7] = value_limb_6_col7;
            let value_limb_7_col8 = memory_id_to_big_value_tmp_e86ad_2.get_m31(7);
            *row[8] = value_limb_7_col8;
            let value_limb_8_col9 = memory_id_to_big_value_tmp_e86ad_2.get_m31(8);
            *row[9] = value_limb_8_col9;
            let value_limb_9_col10 = memory_id_to_big_value_tmp_e86ad_2.get_m31(9);
            *row[10] = value_limb_9_col10;
            let value_limb_10_col11 = memory_id_to_big_value_tmp_e86ad_2.get_m31(10);
            *row[11] = value_limb_10_col11;
            let value_limb_11_col12 = memory_id_to_big_value_tmp_e86ad_2.get_m31(11);
            *row[12] = value_limb_11_col12;
            let value_limb_12_col13 = memory_id_to_big_value_tmp_e86ad_2.get_m31(12);
            *row[13] = value_limb_12_col13;
            let value_limb_13_col14 = memory_id_to_big_value_tmp_e86ad_2.get_m31(13);
            *row[14] = value_limb_13_col14;
            let value_limb_14_col15 = memory_id_to_big_value_tmp_e86ad_2.get_m31(14);
            *row[15] = value_limb_14_col15;

            // Range Check Last Limb Bits In Ms Limb 2.

            // Cond Range Check 2.

            let partial_limb_msb_tmp_e86ad_3 =
                (((PackedUInt16::from_m31(value_limb_14_col15)) & (UInt16_2)) >> (UInt16_1));
            let partial_limb_msb_col16 = partial_limb_msb_tmp_e86ad_3.as_m31();
            *row[16] = partial_limb_msb_col16;

            *sub_component_inputs.memory_id_to_big[0] = value_id_col0;
            *lookup_data.memory_id_to_big_1 = [
                M31_1662111297,
                value_id_col0,
                value_limb_0_col1,
                value_limb_1_col2,
                value_limb_2_col3,
                value_limb_3_col4,
                value_limb_4_col5,
                value_limb_5_col6,
                value_limb_6_col7,
                value_limb_7_col8,
                value_limb_8_col9,
                value_limb_9_col10,
                value_limb_10_col11,
                value_limb_11_col12,
                value_limb_12_col13,
                value_limb_13_col14,
                value_limb_14_col15,
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
            let read_positive_known_id_num_bits_128_output_tmp_e86ad_5 =
                PackedFelt252::from_limbs([
                    value_limb_0_col1,
                    value_limb_1_col2,
                    value_limb_2_col3,
                    value_limb_3_col4,
                    value_limb_4_col5,
                    value_limb_5_col6,
                    value_limb_6_col7,
                    value_limb_7_col8,
                    value_limb_8_col9,
                    value_limb_9_col10,
                    value_limb_10_col11,
                    value_limb_11_col12,
                    value_limb_12_col13,
                    value_limb_13_col14,
                    value_limb_14_col15,
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

            let read_positive_num_bits_128_output_tmp_e86ad_6 = (
                read_positive_known_id_num_bits_128_output_tmp_e86ad_5,
                value_id_col0,
            );

            *lookup_data.mults_0 = M31_1;
        });

    (trace, lookup_data, sub_component_inputs)
}

// === BEGIN witness_genericize (generated; re-runnable) ===
//
// GENERATED by tools/witness_genericize for `range_check_builtin` — mechanical rewrite of
// `write_trace_simd`'s per-row closure into a generic body over `WitnessEval`. Do not
// edit by hand: re-run the tool after upstream regeneration (this block is stripped and
// re-emitted idempotently). The original `write_trace_simd` above is the untouched
// byte-equality baseline (see `witness_eval::differential_test`).
//
// Flat layouts (derived, DECLARATION order):
//   LOOKUP words:
//     memory_address_to_id_0[3] 0..2
//     memory_id_to_big_1[30] 3..32
//     mults_0 33
//     (34 words)
//   SUB-INPUT words:
//     memory_address_to_id[0] 0
//     memory_id_to_big[0] 1
//     (2 words)
use crate::witness::witness_eval::recording::{RecordingOutput, RecordingWitnessEval};
use crate::witness::witness_eval::simd::SimdWitnessEval;
use crate::witness::witness_eval::WitnessEval;

pub(crate) const N_LOOKUP_WORDS: usize = 34;
pub(crate) const N_SUB_INPUT_WORDS: usize = 2;

/// The per-row `range_check_builtin` base-trace body, routed through `WitnessEval`.
/// Mechanical transcription of `write_trace_simd`'s per-row closure (baseline above).
#[allow(clippy::identity_op)]
#[allow(clippy::erasing_op)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn range_check_builtin_row_body<E: WitnessEval>(eval: &mut E) {
    let m31_0 = eval.m31_const(0);
    let m31_1 = eval.m31_const(1);
    let m31_1444891767 = eval.m31_const(1444891767);
    let m31_1662111297 = eval.m31_const(1662111297);
    let seq = eval.iota();
    let wg_v0 = eval.input(0);
    let wg_v1 = eval.m31_add(wg_v0, seq);
    let memory_address_to_id_value_tmp_e86ad_0 = eval.mem_addr_to_id(wg_v1);
    let value_id_col0 = memory_address_to_id_value_tmp_e86ad_0;
    eval.set_col(0, value_id_col0);
    let wg_v2 = eval.input(0);
    let wg_v3 = eval.m31_add(wg_v2, seq);
    eval.set_sub_input_word(0, wg_v3);
    eval.set_lookup_word(0, m31_1444891767);
    let wg_v4 = eval.input(0);
    let wg_v5 = eval.m31_add(wg_v4, seq);
    eval.set_lookup_word(1, wg_v5);
    eval.set_lookup_word(2, value_id_col0);
    let memory_id_to_big_value_tmp_e86ad_2 = eval.mem_id_to_value(value_id_col0);
    let value_limb_0_col1 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 0);
    eval.set_col(1, value_limb_0_col1);
    let value_limb_1_col2 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 1);
    eval.set_col(2, value_limb_1_col2);
    let value_limb_2_col3 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 2);
    eval.set_col(3, value_limb_2_col3);
    let value_limb_3_col4 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 3);
    eval.set_col(4, value_limb_3_col4);
    let value_limb_4_col5 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 4);
    eval.set_col(5, value_limb_4_col5);
    let value_limb_5_col6 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 5);
    eval.set_col(6, value_limb_5_col6);
    let value_limb_6_col7 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 6);
    eval.set_col(7, value_limb_6_col7);
    let value_limb_7_col8 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 7);
    eval.set_col(8, value_limb_7_col8);
    let value_limb_8_col9 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 8);
    eval.set_col(9, value_limb_8_col9);
    let value_limb_9_col10 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 9);
    eval.set_col(10, value_limb_9_col10);
    let value_limb_10_col11 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 10);
    eval.set_col(11, value_limb_10_col11);
    let value_limb_11_col12 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 11);
    eval.set_col(12, value_limb_11_col12);
    let value_limb_12_col13 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 12);
    eval.set_col(13, value_limb_12_col13);
    let value_limb_13_col14 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 13);
    eval.set_col(14, value_limb_13_col14);
    let value_limb_14_col15 = eval.felt_get_m31(&memory_id_to_big_value_tmp_e86ad_2.clone(), 14);
    eval.set_col(15, value_limb_14_col15);
    let wg_v6 = eval.u16_from_m31(value_limb_14_col15);
    let wg_v7 = eval.u16_and(wg_v6, 2);
    let partial_limb_msb_tmp_e86ad_3 = eval.u16_shr(wg_v7, 1);
    let partial_limb_msb_col16 = eval.u16_as_m31(partial_limb_msb_tmp_e86ad_3);
    eval.set_col(16, partial_limb_msb_col16);
    eval.set_sub_input_word(1, value_id_col0);
    eval.set_lookup_word(3, m31_1662111297);
    eval.set_lookup_word(4, value_id_col0);
    eval.set_lookup_word(5, value_limb_0_col1);
    eval.set_lookup_word(6, value_limb_1_col2);
    eval.set_lookup_word(7, value_limb_2_col3);
    eval.set_lookup_word(8, value_limb_3_col4);
    eval.set_lookup_word(9, value_limb_4_col5);
    eval.set_lookup_word(10, value_limb_5_col6);
    eval.set_lookup_word(11, value_limb_6_col7);
    eval.set_lookup_word(12, value_limb_7_col8);
    eval.set_lookup_word(13, value_limb_8_col9);
    eval.set_lookup_word(14, value_limb_9_col10);
    eval.set_lookup_word(15, value_limb_10_col11);
    eval.set_lookup_word(16, value_limb_11_col12);
    eval.set_lookup_word(17, value_limb_12_col13);
    eval.set_lookup_word(18, value_limb_13_col14);
    eval.set_lookup_word(19, value_limb_14_col15);
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
    let read_positive_known_id_num_bits_128_output_tmp_e86ad_5 = eval.felt_from_limbs([
        value_limb_0_col1,
        value_limb_1_col2,
        value_limb_2_col3,
        value_limb_3_col4,
        value_limb_4_col5,
        value_limb_5_col6,
        value_limb_6_col7,
        value_limb_7_col8,
        value_limb_8_col9,
        value_limb_9_col10,
        value_limb_10_col11,
        value_limb_11_col12,
        value_limb_12_col13,
        value_limb_13_col14,
        value_limb_14_col15,
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
    let read_positive_num_bits_128_output_tmp_e86ad_6 = (
        read_positive_known_id_num_bits_128_output_tmp_e86ad_5.clone(),
        value_id_col0,
    );
    eval.set_lookup_word(33, m31_1);
}

/// Generic SIMD driver: same allocation as `write_trace_simd`, but each row runs
/// `range_check_builtin_row_body` on a per-row `SimdWitnessEval`, then reconstructs the concrete
/// `LookupData` / `SubComponentInputs` from the eval's flat scratch. Module-private (it
/// returns the module-private `LookupData` / `SubComponentInputs`; wider visibility would
/// be E0446 and force a change OUTSIDE this block). External callers use the `pub(crate)`
/// `write_trace_generic` method or the `#[cfg(test)]` `generic_simd_diff` harness.
#[allow(clippy::type_complexity)]
#[allow(unused_variables)]
#[allow(dead_code)]
fn write_trace_generic_simd(
    log_size: u32,
    range_check_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
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
                vec![Simd::splat(range_check_builtin_segment_start)],
                row_index,
                &enabler_col,
                N_LOOKUP_WORDS,
                N_SUB_INPUT_WORDS,
            );
            range_check_builtin_row_body(&mut eval);
            let lw = eval.lookup_scratch();
            *lookup_data.memory_address_to_id_0 = [lw[0], lw[1], lw[2]];
            *lookup_data.memory_id_to_big_1 = [
                lw[3], lw[4], lw[5], lw[6], lw[7], lw[8], lw[9], lw[10], lw[11], lw[12], lw[13],
                lw[14], lw[15], lw[16], lw[17], lw[18], lw[19], lw[20], lw[21], lw[22], lw[23],
                lw[24], lw[25], lw[26], lw[27], lw[28], lw[29], lw[30], lw[31], lw[32],
            ];
            *lookup_data.mults_0 = lw[33];
            let sw = eval.sub_scratch();
            *sub_component_inputs.memory_address_to_id[0] =
                unsafe { PackedM31::from_simd_unchecked(sw[0]) };
            *sub_component_inputs.memory_id_to_big[0] =
                unsafe { PackedM31::from_simd_unchecked(sw[1]) };
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
    ) -> (
        ComponentTrace<N_TRACE_COLUMNS>,
        Claim,
        InteractionClaimGenerator,
    ) {
        let log_size = self.log_size;
        let (trace, lookup_data, sub_component_inputs) = write_trace_generic_simd(
            log_size,
            self.range_check_builtin_segment_start,
            memory_address_to_id_state,
            memory_id_to_big_state,
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

/// Record the `range_check_builtin` per-row body into witness-JIT bytecode
/// (statement-independent — recorded once). EXTENDED ops (if any) surface in
/// `RecordingOutput::poison_ops` — the honest ISA-V2 census, not a failure.
#[allow(dead_code)]
pub(crate) fn record_range_check_builtin() -> RecordingOutput {
    let mut eval = RecordingWitnessEval::with_slots("range_check_builtin", 1, Some(2));
    range_check_builtin_row_body(&mut eval);
    eval.finish()
}

crate::jit_lookup_accessor! {
    34;
    memory_address_to_id_0: 3,
    memory_id_to_big_1: 30,
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
    ("memory_id_to_big", 0, "memory_id_to_big_state", 0, 1, 1),
];

/// §6a device-interaction descriptors (facts, COLUMN order): one entry
/// per logup column — (a_field, a_mult, a_neg, b_field, b_mult, b_neg);
/// b_field == "" for a trailing solo column. mult encoding: "1" = one,
/// "enabler" = the real-row enabler, else a scalar lookup-data field.
#[allow(dead_code)]
pub(crate) const JIT_LOGUP_DESCS: &[(&str, &str, bool, &str, &str, bool)] = &[(
    "memory_address_to_id_0",
    "mults_0",
    false,
    "memory_id_to_big_1",
    "mults_0",
    false,
)];

// ---- Test-only surface for the byte-equality gate ---------------------------------

fn lookup_data_flat(ld: &LookupData) -> Vec<Vec<PackedM31>> {
    vec![
        ld.memory_address_to_id_0
            .iter()
            .flatten()
            .copied()
            .collect(),
        ld.memory_id_to_big_1.iter().flatten().copied().collect(),
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
    log_size: u32,
    range_check_builtin_segment_start: u32,
    memory_address_to_id_state: &memory_address_to_id::ClaimGenerator,
    memory_id_to_big_state: &memory_id_to_big::ClaimGenerator,
) -> GenericSimdDiff {
    let (trace_o, ld_o, sci_o) = write_trace_simd(
        log_size.clone(),
        range_check_builtin_segment_start.clone(),
        memory_address_to_id_state,
        memory_id_to_big_state,
    );
    let (trace_g, ld_g, sci_g) = write_trace_generic_simd(
        log_size,
        range_check_builtin_segment_start,
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
    memory_address_to_id_0: Vec<[PackedM31; 3]>,
    memory_id_to_big_1: Vec<[PackedM31; 30]>,
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

        (logup_gen.into_raw(), |claimed_sum| InteractionClaim {
            claimed_sum,
        })
    }
}
