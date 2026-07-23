//! Per-component GPU constraint evaluation.
//!
//! The JIT/AOT lane (kernels generated from THIS build's AIR via the recording
//! evaluator — NVRTC at prove time, or the embedded AOT pack compiled offline)
//! with the generic CPU lane as fallback *on the same accumulator claim*
//! (claiming twice would consume two random-coefficient ranges).
//!
//! The NitrooZK precompiled kernel set was DELETED (design §2, M3): generated
//! against a foreign AIR revision with a raw Rust-struct ABI, it mismatched
//! 100% of rows on every component and no kernel was ever qualified — the AOT
//! pack is its correct replacement (same "precompiled" performance, generated
//! from this build's AIR by construction).
//!
//! `STWO_CUDA_CONSTRAINT_LOG=1` logs the lane taken per component.

use stwo::core::air::Component;
use stwo::core::fields::m31::BaseField;
use stwo::prover::backend::Column;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo::prover::{DomainEvaluationAccumulator, Trace};
use stwo_constraint_framework::{
    accumulate_pointwise_cpu, constraint_quotient_inputs, ConstraintQuotientInputs,
    FrameworkComponent, FrameworkEval,
};

use super::CudaBackend;
use crate::columns::{BaseFieldVec, SecureFieldVec};

/// The log-friendly component name: the module segment preceding the type name
/// (e.g. `cairo_air::components::add_opcode::Eval` -> `add_opcode`).
fn derived_eval_name<E>() -> &'static str {
    let full = core::any::type_name::<E>();
    let full = full.split('<').next().unwrap_or(full);
    let mut segments = full.rsplit("::");
    let _type_name = segments.next();
    segments.next().unwrap_or(full)
}

/// Evaluate a component's constraint quotients: per-component GPU kernel when one
/// exists, CPU pointwise evaluation otherwise — both on a single accumulator claim,
/// mirroring `evaluate_constraint_quotients_via_cpu` exactly.
pub fn evaluate_constraint_quotients<E: FrameworkEval + Sync>(
    component: &FrameworkComponent<E>,
    trace: &Trace<'_, CudaBackend>,
    evaluation_accumulator: &mut DomainEvaluationAccumulator<CudaBackend>,
) {
    if component.n_constraints() == 0 {
        return;
    }

    let ConstraintQuotientInputs {
        eval_domain,
        trace_domain,
        trace,
        denom_inv,
    } = constraint_quotient_inputs(component, trace, evaluation_accumulator.evaluation_mode());

    let [mut accum] =
        evaluation_accumulator.columns([(eval_domain.log_size(), component.n_constraints())]);
    accum.random_coeff_powers.reverse();

    let eval_name = derived_eval_name::<E>();
    let log = std::env::var_os("STWO_CUDA_CONSTRAINT_LOG").is_some();

    // GPU marshaling for the JIT/AOT lane: pointer-table trace ABI — the kernel
    // indexes trace_cols[global_column][row], no flattening copies.
    let gpu_denom_inv = BaseFieldVec::from_vec(denom_inv.clone());
    let random_coeff_powers = SecureFieldVec::from_vec(accum.random_coeff_powers.clone());
    let trace_ptrs: Vec<Vec<*const u32>> = (0..3)
        .map(|interaction| {
            trace
                .get(interaction)
                .map(|columns| {
                    columns
                        .iter()
                        .map(|column| column.values.device_ptr)
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();
    let trace_column_lens: Vec<Vec<usize>> = (0..3)
        .map(|interaction| {
            trace
                .get(interaction)
                .map(|columns| columns.iter().map(|column| column.values.len()).collect())
                .unwrap_or_default()
        })
        .collect();

    // JIT lane: kernels generated from THIS build's AIR via the recording evaluator
    // (NVRTC, content-hash cached) — consistent by construction, explicit C ABI.
    // The fused kernel adds into the accumulator coordinates IN PLACE (no scratch,
    // no separate accumulate pass), so the verify-mode snapshot must be taken before
    // the launch. A `false` return guarantees the accumulator was not touched.
    let verify = std::env::var_os("STWO_CUDA_CONSTRAINT_VERIFY").is_some();
    let accum_prev_snapshot = if verify {
        Some(SecureColumnByCoords {
            columns: accum.col.columns.each_ref().map(|column| column.to_cpu()),
        })
    } else {
        None
    };
    if super::jit::try_jit_constraint_quotients(
        component,
        &super::jit::JitInputs {
            trace_ptrs: &trace_ptrs,
            trace_column_lens: &trace_column_lens,
            random_coeff_powers: &random_coeff_powers,
            denom_inv: &gpu_denom_inv,
            accum_coords: [
                accum.col.columns[0].device_ptr.cast_mut(),
                accum.col.columns[1].device_ptr.cast_mut(),
                accum.col.columns[2].device_ptr.cast_mut(),
                accum.col.columns[3].device_ptr.cast_mut(),
            ],
            n_rows: eval_domain.size(),
            trace_log_size: trace_domain.log_size(),
        },
    ) {
        if log {
            eprintln!("stwo-backend-cuda constraint eval: component={eval_name} lane=JIT");
        }
        if let Some(snapshot) = accum_prev_snapshot {
            let gpu_result: Vec<Vec<BaseField>> = accum
                .col
                .columns
                .iter()
                .map(|column| column.to_cpu())
                .collect();
            let trace_cols_cpu = trace
                .as_cols_ref()
                .map_cols(|column| CircleEvaluation::new(column.domain, column.values.to_cpu()));
            let cpu_result = accumulate_pointwise_cpu(
                component,
                trace_cols_cpu.as_cols_ref(),
                eval_domain.log_size(),
                trace_domain.log_size(),
                denom_inv.clone(),
                &accum.random_coeff_powers,
                &snapshot,
            );
            let mut mismatches = 0usize;
            let mut first: Option<(usize, usize)> = None;
            for (coord, gpu_column) in gpu_result.iter().enumerate() {
                for (row, (gpu, cpu)) in gpu_column
                    .iter()
                    .zip(cpu_result.columns[coord].iter())
                    .enumerate()
                {
                    if gpu != cpu {
                        mismatches += 1;
                        if first.is_none() {
                            first = Some((coord, row));
                        }
                    }
                }
            }
            let total = 4 * gpu_result[0].len();
            eprintln!(
                "VERIFY-JIT component={eval_name}: {mismatches}/{total} mismatched, first={first:?}"
            );
            if mismatches > 0 {
                *accum.col = SecureColumnByCoords {
                    columns: cpu_result
                        .columns
                        .map(|values| values.into_iter().collect()),
                };
            }
        }
        return;
    }
    if log {
        eprintln!("stwo-backend-cuda constraint eval: component={eval_name} lane=CPU");
    }

    // CPU fallback on the SAME accumulator claim, mirroring
    // `evaluate_constraint_quotients_via_cpu`'s body.
    let trace_cols_cpu = trace
        .as_cols_ref()
        .map_cols(|column| CircleEvaluation::new(column.domain, column.values.to_cpu()));
    let accum_prev_cpu = SecureColumnByCoords {
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
