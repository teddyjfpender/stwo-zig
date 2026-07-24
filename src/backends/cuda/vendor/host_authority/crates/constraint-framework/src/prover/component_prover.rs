use std::borrow::Cow;

use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use stwo::core::air::Component;
use stwo::core::constraints::coset_vanishing;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo::core::poly::circle::{CanonicCoset, CircleDomain};
use stwo::core::utils::bit_reverse;
use stwo::prover::backend::simd::column::VeryPackedSecureColumnByCoords;
use stwo::prover::backend::simd::m31::LOG_N_LANES;
use stwo::prover::backend::simd::very_packed_m31::{VeryPackedBaseField, LOG_N_VERY_PACKED_ELEMS};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::{Backend, Column, CpuBackend};
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::{ComponentProver, DomainEvaluationAccumulator, EvaluationMode, Poly, Trace};
use tracing::{span, Level};

use super::{CpuDomainEvaluator, SimdDomainEvaluator};
use crate::{FrameworkComponent, FrameworkEval, PREPROCESSED_TRACE_IDX};

/// Number of `VeryPacked` rows processed per (parallel) task. Amortizes task-scheduling
/// overhead while keeping enough tasks for load balancing on wide machines.
const CHUNK_SIZE: usize = 8;
// The chunked iteration below requires the effective chunk size to divide the (power-of-two)
// number of rows; rows beyond `n_chunks * chunk_size` would silently be skipped otherwise.
const _: () = assert!(CHUNK_SIZE.is_power_of_two());

/// Common inputs for constraint quotient evaluation, shared between the SIMD and CPU backends.
/// The shared inputs every constraint-quotient evaluation lane consumes: the component's
/// trace columns prepared for the evaluation domain, and the quotient denominators.
/// Exposed so out-of-tree backends (e.g. GPU lanes) can mirror the CPU lane exactly.
pub struct ConstraintQuotientInputs<'a, B: Backend> {
    pub eval_domain: CircleDomain,
    pub trace_domain: CanonicCoset,
    pub trace: TreeVec<Vec<Cow<'a, CircleEvaluation<B, BaseField, BitReversedOrder>>>>,
    pub denom_inv: Vec<BaseField>,
}

/// Public entry to [`get_constraint_quotient_inputs`] for backend drivers.
pub fn constraint_quotient_inputs<'a, E: FrameworkEval, B: Backend>(
    component: &FrameworkComponent<E>,
    trace: &'a Trace<'a, B>,
    mode: EvaluationMode,
) -> ConstraintQuotientInputs<'a, B> {
    get_constraint_quotient_inputs(component, trace, mode)
}

/// Prepares trace evaluations: borrows directly (subdomain) or extends to eval domain.
fn get_trace_columns<'a, B: Backend>(
    component_polys: TreeVec<Vec<&'a &Poly<B>>>,
    eval_domain: CircleDomain,
    mode: EvaluationMode,
) -> TreeVec<Vec<Cow<'a, CircleEvaluation<B, BaseField, BitReversedOrder>>>> {
    match mode {
        EvaluationMode::SubDomain { .. } => {
            // Borrow committed evaluations directly. Only the first
            // 2^max_constraint_log_degree_bound indices are going to be used for the
            // constraint quotient evaluation (in bit-reversed order these form the
            // subdomain coset).
            //
            // Ideally we'd slice to just those indices, but the type system requires
            // borrowing the entire evaluation.
            component_polys.map_cols(|c| Cow::Borrowed(&c.evals))
        }
        EvaluationMode::ExtendToEvalDomain => {
            let _span = span!(Level::INFO, "Constraint Extension").entered();
            let twiddles = B::precompute_twiddles(eval_domain.half_coset);
            #[cfg(not(feature = "parallel"))]
            {
                component_polys.as_cols_ref().map_cols(|col| {
                    Cow::Owned(col.get_evaluation_on_domain(eval_domain, &twiddles))
                })
            }
            #[cfg(feature = "parallel")]
            {
                component_polys.as_cols_ref().par_map_cols(|col| {
                    Cow::Owned(col.get_evaluation_on_domain(eval_domain, &twiddles))
                })
            }
        }
    }
}

/// Constructs the inputs needed for constraint quotient evaluation from a component and trace.
/// Computes the eval/trace domains, prepares trace columns (borrowing or extending as needed),
/// and precomputes denominator inverses.
fn get_constraint_quotient_inputs<'a, E: FrameworkEval, B: Backend>(
    component: &FrameworkComponent<E>,
    trace: &'a Trace<'a, B>,
    mode: EvaluationMode,
) -> ConstraintQuotientInputs<'a, B> {
    let max_constraint_log_degree_bound = component.max_constraint_log_degree_bound();
    let trace_domain = CanonicCoset::new(component.eval.log_size());

    let mut component_polys = trace.polys.sub_tree(&component.trace_locations);
    component_polys[PREPROCESSED_TRACE_IDX] = component
        .preprocessed_column_indices
        .iter()
        .map(|idx| &trace.polys[PREPROCESSED_TRACE_IDX][*idx])
        .collect();

    let eval_domain = match mode {
        EvaluationMode::SubDomain { log_expansion } => {
            subdomain_eval_domain(max_constraint_log_degree_bound, log_expansion)
        }
        EvaluationMode::ExtendToEvalDomain => {
            CanonicCoset::new(max_constraint_log_degree_bound).circle_domain()
        }
    };
    let trace = get_trace_columns(component_polys, eval_domain, mode);

    // Denom inverses.
    let log_expand = eval_domain.log_size() - trace_domain.log_size();
    let mut denom_inv = (0..1 << log_expand)
        .map(|i| coset_vanishing(trace_domain.coset(), eval_domain.at(i)).inverse())
        .collect_vec();
    bit_reverse(&mut denom_inv);

    ConstraintQuotientInputs {
        eval_domain,
        trace_domain,
        trace,
        denom_inv,
    }
}

/// The backend extension point of the constraint framework.
///
/// Implementing this trait for a backend makes every [`FrameworkComponent<E>`] a
/// [`ComponentProver`] for that backend, through the single blanket impl below. This exists
/// because Rust's orphan rules prevent an out-of-tree backend crate from writing
/// `impl<E> ComponentProver<TheirBackend> for FrameworkComponent<E>` directly (`E` is an
/// uncovered foreign type parameter); implementing `FrameworkBackend` for their (local)
/// backend type is allowed.
pub trait FrameworkBackend: Backend {
    /// Evaluates the constraint quotients of `component` on the evaluation domain and
    /// accumulates them in `evaluation_accumulator`.
    fn evaluate_constraint_quotients_on_domain<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &Trace<'_, Self>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<Self>,
    );
}

impl<E: FrameworkEval + Sync, B: FrameworkBackend> ComponentProver<B> for FrameworkComponent<E> {
    fn evaluate_constraint_quotients_on_domain(
        &self,
        trace: &Trace<'_, B>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
    ) {
        B::evaluate_constraint_quotients_on_domain(self, trace, evaluation_accumulator);
    }
}

impl FrameworkBackend for SimdBackend {
    fn evaluate_constraint_quotients_on_domain<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &Trace<'_, SimdBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<SimdBackend>,
    ) {
        if component.n_constraints() == 0 {
            return;
        }

        let ConstraintQuotientInputs {
            eval_domain,
            trace_domain,
            trace,
            denom_inv,
        } = get_constraint_quotient_inputs(
            component,
            trace,
            evaluation_accumulator.evaluation_mode(),
        );

        let [mut accum] =
            evaluation_accumulator.columns([(eval_domain.log_size(), component.n_constraints())]);
        accum.random_coeff_powers.reverse();

        let _span = span!(
            Level::INFO,
            "Constraint point-wise eval",
            class = "ConstraintEval"
        )
        .entered();

        // Fall back to CPU if the trace is too small.
        if trace_domain.log_size() < LOG_N_LANES + LOG_N_VERY_PACKED_ELEMS {
            let trace_cols = trace.as_cols_ref().map_cols(|c| c.to_cpu());
            let trace_cols = trace_cols.as_cols_ref();
            *accum.col = SecureColumnByCoords::from_cpu(accumulate_pointwise_cpu(
                component,
                trace_cols,
                eval_domain.log_size(),
                trace_domain.log_size(),
                denom_inv,
                &accum.random_coeff_powers,
                &accum.col.to_cpu(),
            ));
            return;
        }

        let col = unsafe { VeryPackedSecureColumnByCoords::transform_under_mut(accum.col) };

        // NOTE: `col` is a transmuted view whose inner lengths are still counted in
        // `PackedBaseField` units, so its chunk iterators yield more chunks than there are real
        // `VeryPacked` rows. Only the first `n_chunks` chunks may be consumed.
        let n_vec_rows: usize =
            1 << (eval_domain.log_size() - LOG_N_LANES - LOG_N_VERY_PACKED_ELEMS);
        // Both are powers of two, so `chunk_size` always divides `n_vec_rows`.
        let chunk_size = CHUNK_SIZE.min(n_vec_rows);
        let n_chunks = n_vec_rows / chunk_size;

        #[cfg(not(feature = "parallel"))]
        let iter = col.chunks_mut(chunk_size).take(n_chunks).enumerate();

        #[cfg(feature = "parallel")]
        let iter = col.par_chunks_mut(chunk_size).take(n_chunks).enumerate();

        // Define any component values outside the loop to prevent the compiler thinking there
        // is a `Sync` requirement on the component type.
        let self_eval = &component.eval;
        let self_claimed_sum = component.claimed_sum;

        // Build the column reference tree once; rebuilding it per row allocates a vector of
        // references per column tree and dominates the loop for wide traces.
        let trace_cols = trace.as_cols_ref().map_cols(|c| c.as_ref());

        iter.for_each(|(chunk_idx, mut chunk)| {
            for idx_in_chunk in 0..chunk_size {
                let vec_row = chunk_idx * chunk_size + idx_in_chunk;
                // Evaluate constrains at row.
                let eval = SimdDomainEvaluator::new(
                    &trace_cols,
                    vec_row,
                    &accum.random_coeff_powers,
                    trace_domain.log_size(),
                    eval_domain.log_size(),
                    self_eval.log_size(),
                    self_claimed_sum,
                );
                let row_res = self_eval.evaluate(eval).row_res;

                // Finalize row.
                unsafe {
                    let row_denom_inv = VeryPackedBaseField::broadcast(
                        denom_inv[vec_row
                            >> (trace_domain.log_size() - LOG_N_LANES - LOG_N_VERY_PACKED_ELEMS)],
                    );
                    chunk.set_packed(
                        idx_in_chunk,
                        chunk.packed_at(idx_in_chunk) + row_res * row_denom_inv,
                    )
                }
            }
        });
    }
}

impl FrameworkBackend for CpuBackend {
    fn evaluate_constraint_quotients_on_domain<E: FrameworkEval + Sync>(
        component: &FrameworkComponent<E>,
        trace: &Trace<'_, CpuBackend>,
        evaluation_accumulator: &mut DomainEvaluationAccumulator<CpuBackend>,
    ) {
        if component.n_constraints() == 0 {
            return;
        }

        let ConstraintQuotientInputs {
            eval_domain,
            trace_domain,
            trace,
            denom_inv,
        } = get_constraint_quotient_inputs(
            component,
            trace,
            evaluation_accumulator.evaluation_mode(),
        );

        let [mut accum] =
            evaluation_accumulator.columns([(eval_domain.log_size(), component.n_constraints())]);
        accum.random_coeff_powers.reverse();

        let _span = span!(
            Level::INFO,
            "Constraint point-wise eval",
            class = "ConstraintEval"
        )
        .entered();
        let trace_cols = trace.as_cols_ref().map_cols(|c| c.as_ref());

        *accum.col = accumulate_pointwise_cpu(
            component,
            trace_cols,
            eval_domain.log_size(),
            trace_domain.log_size(),
            denom_inv,
            &accum.random_coeff_powers,
            accum.col,
        );
    }
}

/// Evaluates a component's constraint quotients by converting the trace columns to the
/// [`CpuBackend`], evaluating there, and writing the result back into the backend-typed
/// accumulator.
///
/// This is a correct-but-slow generic driver that lets a new backend implement
/// [`FrameworkBackend`] (and so become fully provable) before it has a native constraint
/// evaluator. Backends should replace it with a native implementation for performance.
///
/// NOTE: when `EvaluationMode::ExtendToEvalDomain` is used, the backend's coefficient
/// representation must match the CPU backend's (plain bit-reversed order).
pub fn evaluate_constraint_quotients_via_cpu<E: FrameworkEval + Sync, B: Backend>(
    component: &FrameworkComponent<E>,
    trace: &Trace<'_, B>,
    evaluation_accumulator: &mut DomainEvaluationAccumulator<B>,
) {
    if component.n_constraints() == 0 {
        return;
    }

    let ConstraintQuotientInputs {
        eval_domain,
        trace_domain,
        trace,
        denom_inv,
    } = get_constraint_quotient_inputs(component, trace, evaluation_accumulator.evaluation_mode());

    let [mut accum] =
        evaluation_accumulator.columns([(eval_domain.log_size(), component.n_constraints())]);
    accum.random_coeff_powers.reverse();

    let _span = span!(
        Level::INFO,
        "Constraint point-wise eval",
        class = "ConstraintEval"
    )
    .entered();

    // Convert the (borrowed or extended) trace columns and the accumulator to the CPU
    // backend, evaluate, and write back.
    let trace_cols_cpu: TreeVec<Vec<CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>> =
        trace
            .as_cols_ref()
            .map_cols(|column| CircleEvaluation::new(column.domain, column.values.to_cpu()));
    let accum_prev_cpu = SecureColumnByCoords::<CpuBackend> {
        columns: accum.col.columns.each_ref().map(|column| column.to_cpu()),
    };

    let result = accumulate_pointwise_cpu(
        component,
        trace_cols_cpu.as_cols_ref(),
        eval_domain.log_size(),
        trace_domain.log_size(),
        denom_inv,
        &accum.random_coeff_powers,
        &accum_prev_cpu,
    );

    *accum.col = SecureColumnByCoords {
        columns: result.columns.map(|values| values.into_iter().collect()),
    };
}

/// Computes the evaluation subdomain for a component given its constraint degree bound
/// and the log_expansion from `EvaluationMode::SubDomain`.
///
/// When `log_expansion == 0`, returns the canonical domain.
/// When `log_expansion > 0`, returns the first subdomain obtained by splitting the
/// committed domain `log_expansion` times.
fn subdomain_eval_domain(max_constraint_log_degree_bound: u32, log_expansion: u32) -> CircleDomain {
    let committed_domain =
        CanonicCoset::new(max_constraint_log_degree_bound + log_expansion).circle_domain();
    committed_domain.split(log_expansion).0
}

/// Pointwise CPU constraint evaluation over prepared trace columns. Public so backend
/// drivers with their own GPU lane can fall back onto an already-claimed accumulator
/// (claiming twice would consume two random-coefficient ranges).
pub fn accumulate_pointwise_cpu<E: FrameworkEval + Sync>(
    component: &FrameworkComponent<E>,
    trace_cols: TreeVec<Vec<&CircleEvaluation<CpuBackend, BaseField, BitReversedOrder>>>,
    eval_log_size: u32,
    trace_log_size: u32,
    denom_inv: Vec<BaseField>,
    random_coeff_powers: &[SecureField],
    accum: &SecureColumnByCoords<CpuBackend>,
) -> SecureColumnByCoords<CpuBackend> {
    // Capture only `Sync` pieces: the component itself holds a non-Sync info cache.
    let component_eval = &component.eval;
    let component_log_size = component.eval.log_size();
    let claimed_sum = component.claimed_sum;
    // Rows are independent; evaluate them in parallel and scatter into the column.
    let rows: Vec<SecureField> = stwo::parallel_iter!(0..(1usize << eval_log_size))
        .map(|row| {
            // Evaluate constrains at row.
            let eval = CpuDomainEvaluator::new(
                &trace_cols,
                row,
                random_coeff_powers,
                trace_log_size,
                eval_log_size,
                component_log_size,
                claimed_sum,
            );
            let row_res = component_eval.evaluate(eval).row_res;

            // Finalize row.
            let row_denom_inv = denom_inv[row >> trace_log_size];
            accum.at(row) + row_res * row_denom_inv
        })
        .collect();
    let mut res = SecureColumnByCoords::zeros(1 << eval_log_size);
    for (row, value) in rows.into_iter().enumerate() {
        res.set(row, value);
    }
    res
}
