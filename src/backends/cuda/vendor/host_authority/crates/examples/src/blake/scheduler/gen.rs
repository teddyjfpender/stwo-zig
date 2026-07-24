use std::simd::u32x16;

use itertools::{chain, Itertools};
use num_traits::Zero;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::ColumnVec;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::backend::simd::{blake2s, SimdBackend};
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo_constraint_framework::{
    FractionWriter, LogupTraceGenerator, Relation, ORIGINAL_TRACE_IDX,
};
use tracing::{span, Level};

use super::{blake_scheduler_info, BlakeElements};
use crate::blake::round::{BlakeRoundInput, RoundElements};
#[cfg(feature = "parallel")]
use crate::blake::UnsafeSharedRows;
use crate::blake::{to_felts, N_ROUNDS, N_ROUND_INPUT_FELTS, STATE_SIZE};

#[derive(Copy, Clone, Default)]
pub struct BlakeInput {
    pub v: [u32x16; STATE_SIZE],
    pub m: [u32x16; STATE_SIZE],
}

pub struct BlakeSchedulerLookupData {
    pub round_lookups: [[BaseColumn; N_ROUND_INPUT_FELTS]; N_ROUNDS],
    pub blake_lookups: [BaseColumn; N_ROUND_INPUT_FELTS],
}
impl BlakeSchedulerLookupData {
    fn new(log_size: u32) -> Self {
        Self {
            round_lookups: std::array::from_fn(|_| {
                std::array::from_fn(|_| unsafe { BaseColumn::uninitialized(1 << log_size) })
            }),
            blake_lookups: std::array::from_fn(|_| unsafe {
                BaseColumn::uninitialized(1 << log_size)
            }),
        }
    }
}

pub fn gen_trace(
    log_size: u32,
    inputs: &[BlakeInput],
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    BlakeSchedulerLookupData,
    Vec<BlakeRoundInput>,
) {
    let _span = span!(Level::INFO, "Scheduler Generation").entered();
    let mut lookup_data = BlakeSchedulerLookupData::new(log_size);
    let n_vec_rows = 1usize << (log_size - LOG_N_LANES);
    let mut round_inputs = vec![BlakeRoundInput::default(); n_vec_rows * N_ROUNDS];

    let mut trace = (0..blake_scheduler_info().mask_offsets[ORIGINAL_TRACE_IDX].len())
        .map(|_| unsafe { BaseColumn::uninitialized(1 << log_size) })
        .collect_vec();

    // Generates one row. Each row writes only its own `vec_row` slot of every column, so rows
    // can be generated in parallel.
    let gen_row = |vec_row: usize,
                   trace: &mut Vec<BaseColumn>,
                   lookup_data: &mut BlakeSchedulerLookupData,
                   round_inputs_row: &mut [BlakeRoundInput]| {
        let mut col_index = 0;

        let mut write_u32_array = |x: [u32x16; STATE_SIZE], col_index: &mut usize| {
            x.iter().for_each(|x| {
                to_felts(x).iter().for_each(|x| {
                    trace[*col_index].data[vec_row] = *x;
                    *col_index += 1;
                });
            });
        };

        let BlakeInput { mut v, m } = inputs.get(vec_row).copied().unwrap_or_default();
        let initial_v = v;
        write_u32_array(m, &mut col_index);
        write_u32_array(v, &mut col_index);

        for (r, round_input) in round_inputs_row.iter_mut().enumerate() {
            let prev_v = v;
            blake2s::round(&mut v, m, r);
            write_u32_array(v, &mut col_index);

            let round_m = blake2s::SIGMA[r].map(|i| m[i as usize]);
            *round_input = BlakeRoundInput {
                v: prev_v,
                m: round_m,
            };

            chain![
                prev_v.iter().flat_map(to_felts),
                v.iter().flat_map(to_felts),
                round_m.iter().flat_map(to_felts)
            ]
            .enumerate()
            .for_each(|(i, val)| lookup_data.round_lookups[r][i].data[vec_row] = val);
        }

        chain![
            initial_v.iter().flat_map(to_felts),
            v.iter().flat_map(to_felts),
            m.iter().flat_map(to_felts)
        ]
        .enumerate()
        .for_each(|(i, val)| lookup_data.blake_lookups[i].data[vec_row] = val);
    };

    #[cfg(not(feature = "parallel"))]
    for (vec_row, round_inputs_row) in round_inputs.chunks_mut(N_ROUNDS).enumerate() {
        gen_row(vec_row, &mut trace, &mut lookup_data, round_inputs_row);
    }
    #[cfg(feature = "parallel")]
    {
        let trace_ptr = UnsafeSharedRows(&raw mut trace);
        let lookup_data_ptr = UnsafeSharedRows(&raw mut lookup_data);
        round_inputs.par_chunks_mut(N_ROUNDS).enumerate().for_each(
            |(vec_row, round_inputs_row)| {
                // SAFETY: each row writes only its own `vec_row` slot of every column.
                let trace = unsafe { trace_ptr.get() };
                let lookup_data = unsafe { lookup_data_ptr.get() };
                gen_row(vec_row, trace, lookup_data, round_inputs_row);
            },
        );
    }

    let domain = CanonicCoset::new(log_size).circle_domain();
    let trace = trace
        .into_iter()
        .map(|eval| CircleEvaluation::new(domain, eval))
        .collect();

    (trace, lookup_data, round_inputs)
}
pub fn gen_interaction_trace(
    log_size: u32,
    lookup_data: BlakeSchedulerLookupData,
    round_lookup_elements: &RoundElements,
    blake_lookup_elements: &BlakeElements,
) -> (
    ColumnVec<CircleEvaluation<SimdBackend, BaseField, BitReversedOrder>>,
    SecureField,
) {
    let _span = span!(Level::INFO, "Generate scheduler interaction trace").entered();

    let mut logup_gen = LogupTraceGenerator::new(log_size);

    for [l0, l1] in lookup_data.round_lookups.array_chunks::<2>() {
        let mut col_gen = logup_gen.new_col();

        let write_row = |vec_row: usize, writer: FractionWriter<'_>| {
            let p0: PackedSecureField =
                round_lookup_elements.combine(&l0.each_ref().map(|l| l.data[vec_row]));
            let p1: PackedSecureField =
                round_lookup_elements.combine(&l1.each_ref().map(|l| l.data[vec_row]));
            writer.write_frac(p0 + p1, p0 * p1);
        };
        #[cfg(not(feature = "parallel"))]
        col_gen
            .iter_mut()
            .enumerate()
            .for_each(|(vec_row, writer)| write_row(vec_row, writer));
        #[cfg(feature = "parallel")]
        col_gen
            .par_iter_mut()
            .enumerate()
            .for_each(|(vec_row, writer)| write_row(vec_row, writer));

        col_gen.finalize_col();
    }

    // Last pair. If the number of round is odd (as in blake3), we combine that last round lookup
    // with the entire blake lookup.
    let mut col_gen = logup_gen.new_col();
    let write_row = |vec_row: usize, writer: FractionWriter<'_>| {
        let p_blake: PackedSecureField = blake_lookup_elements.combine(
            &lookup_data
                .blake_lookups
                .each_ref()
                .map(|l| l.data[vec_row]),
        );
        if N_ROUNDS % 2 == 1 {
            let p_round: PackedSecureField = round_lookup_elements.combine(
                &lookup_data.round_lookups[N_ROUNDS - 1]
                    .each_ref()
                    .map(|l| l.data[vec_row]),
            );
            // TODO(alont): Remove.
            writer.write_frac(p_blake, p_round * p_blake);
        } else {
            // TODO(alont): Remove.
            writer.write_frac(PackedSecureField::zero(), p_blake);
        }
    };
    #[cfg(not(feature = "parallel"))]
    col_gen
        .iter_mut()
        .enumerate()
        .for_each(|(vec_row, writer)| write_row(vec_row, writer));
    #[cfg(feature = "parallel")]
    col_gen
        .par_iter_mut()
        .enumerate()
        .for_each(|(vec_row, writer)| write_row(vec_row, writer));
    col_gen.finalize_col();

    logup_gen.finalize_last()
}
