//! JIT GPU constraint-evaluation lane.
//!
//! Records a [`FrameworkEval`]'s constraint tree to V1 bytecode (once per component
//! type), compiles it to a Metal kernel (cached by semantic hash), and evaluates the
//! constraint quotients on the GPU with a single fused dispatch (constraint eval +
//! `denom_inv` multiply + coordinate unpack).
//!
//! Falls back to the CPU lane
//! ([`stwo_constraint_framework::evaluate_constraint_quotients_via_cpu`]) on any recording,
//! compilation, or dispatch failure — correctness never depends on this lane succeeding.
//! Byte-equality with the CPU lane is enforced by the testkit's proof-equality gate.

mod program;
mod recording;
mod shader;

use program::{
    execute_fused_composition_v1, lower_framework_eval_to_v1_with_logup,
    MetalEvaluationProgramExecutionError, MetalEvaluationProgramLoweringError,
};
use stwo::core::air::Component;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::{AccumulationOps, DomainEvaluationAccumulator, Trace};
use stwo_backend_metal_sys::metal::U32Buffer;
use stwo_constraint_framework::{
    constraint_quotient_inputs, ConstraintQuotientInputs, FrameworkComponent, FrameworkEval,
};

use super::MetalBackend;
use crate::columns::BaseFieldVec;

/// Why the JIT lane declined or failed; the caller falls back to the CPU lane.
/// Fields exist for the `Debug` diagnostics behind `STWO_METAL_JIT_LOG`.
#[derive(Debug)]
#[allow(dead_code)]
pub enum JitUnavailable {
    Lowering(MetalEvaluationProgramLoweringError),
    Execution(MetalEvaluationProgramExecutionError),
    Shape(String),
}

/// Evaluate a component's constraint quotients on the GPU.
///
/// Mirrors `evaluate_constraint_quotients_via_cpu` exactly:
/// `accum[row] += random_coeff_powers · constraints(row) * denom_inv[row >> trace_log]`,
/// with the same (reversed) random-coefficient power order and the same trace inputs.
pub fn evaluate_constraint_quotients_via_jit<E: FrameworkEval>(
    component: &FrameworkComponent<E>,
    trace: &Trace<'_, MetalBackend>,
    evaluation_accumulator: &mut DomainEvaluationAccumulator<MetalBackend>,
) -> Result<(), JitUnavailable> {
    if component.n_constraints() == 0 {
        return Ok(());
    }
    if std::env::var_os("STWO_METAL_DISABLE_JIT").is_some() {
        return Err(JitUnavailable::Shape("disabled by env".into()));
    }

    let ConstraintQuotientInputs {
        eval_domain,
        trace_domain,
        trace,
        denom_inv,
    } = constraint_quotient_inputs(component, trace, evaluation_accumulator.evaluation_mode());

    // Record the constraint program (cheap; cached downstream by semantic hash).
    let program = lower_framework_eval_to_v1_with_logup(
        component.evaluator(),
        trace.len() as u32,
        0,
        0,
        component.claimed_sum(),
        component.evaluator().log_size(),
    )
    .map_err(JitUnavailable::Lowering)?;

    let n_rows = eval_domain.size();

    // Flatten the (already extended or borrowed-larger) trace columns into one
    // column-major GPU buffer of `n_rows` rows per column, in tree order. Columns in
    // SubDomain mode are longer than `n_rows`; the first `n_rows` bit-reversed entries
    // form the evaluation subdomain (same prefix the CPU lane indexes).
    let n_columns: usize = trace.iter().map(|interaction| interaction.len()).sum();
    let mut flat = U32Buffer::uninitialized(n_columns * n_rows)
        .map_err(|e| JitUnavailable::Shape(format!("trace concat alloc: {}", e.message())))?;
    let mut interaction_offsets: Vec<u32> = Vec::with_capacity(trace.len());
    let mut next_column = 0u32;
    for interaction in trace.iter() {
        interaction_offsets.push(next_column);
        for column in interaction.iter() {
            assert!(
                column.values.len() >= n_rows,
                "column shorter than eval domain"
            );
            flat.copy_range_from(
                &column.values.buffer,
                0,
                n_rows,
                next_column as usize * n_rows,
            )
            .map_err(|e| JitUnavailable::Shape(format!("trace concat copy: {}", e.message())))?;
            next_column += 1;
        }
    }

    let [mut accum] =
        evaluation_accumulator.columns([(eval_domain.log_size(), component.n_constraints())]);
    accum.random_coeff_powers.reverse();

    let coords = execute_fused_composition_v1(
        &program,
        &flat,
        &interaction_offsets,
        n_rows,
        &accum.random_coeff_powers,
        &denom_inv,
        trace_domain.log_size(),
    )
    .map_err(JitUnavailable::Execution)?;

    // accum[row] += jit_result[row]  (exact field arithmetic; same value as the CPU
    // lane's `accum.at(row) + row_res * denom_inv`).
    let jit_column = SecureColumnByCoords::<MetalBackend> {
        columns: coords.map(BaseFieldVec::from_buffer),
    };
    debug_assert_eq!(
        stwo::prover::backend::Column::len(&jit_column.columns[0]),
        stwo::prover::backend::Column::len(&accum.col.columns[0])
    );
    <MetalBackend as AccumulationOps>::accumulate(accum.col, &jit_column);

    Ok(())
}

/// Convenience used by tests: whether the JIT lane would even try.
#[allow(dead_code)]
pub fn jit_enabled() -> bool {
    std::env::var_os("STWO_METAL_DISABLE_JIT").is_none()
}
