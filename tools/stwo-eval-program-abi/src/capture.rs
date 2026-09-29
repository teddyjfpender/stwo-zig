//! Capture of one `FrameworkComponent` into a bundle component.
//!
//! The component is recorded twice: once with the AIR's real lookup elements and claimed sum, and
//! once with probe elements drawn from a second seed and [`PROBE_CLAIMED_SUM`]. Extension
//! constants that differ between the two recordings are proof-dependent; they are turned into
//! typed runtime parameters (`parameters::classify`), the original values are bound back, and the
//! reconstruction must equal the concrete recording byte for byte before the component is kept.

use anyhow::{Result, anyhow, ensure};
use stwo::core::air::Component;
use stwo::core::fields::qm31::SecureField;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval};

use super::bundle::CapturedComponent;
use super::parameters::{self, LookupProbe};
use super::program::lower_framework_eval_to_v1_with_logup;
use super::semantic;

/// The claimed sum of every probe recording.
pub const PROBE_CLAIMED_SUM: SecureField = SecureField::from_u32_unchecked(257, 263, 269, 271);

/// Running totals over the captured components.
#[derive(Default)]
pub struct Summary {
    pub components: usize,
    pub constraints: usize,
    pub base_instructions: usize,
    pub extension_instructions: usize,
    pub extension_parameters: usize,
}

/// Captures `component` (and its `probe_component` twin), returning it with a one-line report.
pub fn lower_component<E: FrameworkEval, R>(
    name: &str,
    instance: u32,
    component: &FrameworkComponent<E>,
    probe_component: &FrameworkComponent<E>,
    lookup: &LookupProbe<R>,
    probe_lookup: &LookupProbe<R>,
    summary: &mut Summary,
) -> Result<(CapturedComponent, String)> {
    // `FrameworkComponent` derefs to its evaluator in every supported Stwo revision.
    let eval: &E = component;
    let probe_eval: &E = probe_component;
    let random_coefficient_offset = summary.constraints;
    let concrete_program = lower_framework_eval_to_v1_with_logup(
        eval,
        component.trace_locations().len() as u32,
        0,
        0,
        component.claimed_sum(),
        eval.log_size(),
    )
    .map_err(|error| anyhow!("{name}: {error:?}"))?;
    semantic::validate(name, eval, component.claimed_sum(), &concrete_program)?;
    let probe = lower_framework_eval_to_v1_with_logup(
        probe_eval,
        probe_component.trace_locations().len() as u32,
        0,
        0,
        PROBE_CLAIMED_SUM,
        probe_eval.log_size(),
    )
    .map_err(|error| anyhow!("{name} probe: {error:?}"))?;
    let (program, parameter_pairs) = concrete_program
        .parameterize_extension_constants(&probe)
        .map_err(|error| anyhow!("{name}: {error:?}"))?;
    let rebound = program
        .bind_extension_parameters(
            &parameter_pairs
                .iter()
                .map(|parameter| parameter.primary)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| anyhow!("{name} rebound: {error:?}"))?;
    ensure!(
        rebound == concrete_program,
        "{name}: parameterized AIR does not reconstruct its concrete recording"
    );
    let sources = parameters::classify(
        name,
        eval.log_size(),
        component.claimed_sum(),
        PROBE_CLAIMED_SUM,
        lookup,
        probe_lookup,
        &parameter_pairs,
    )?;
    ensure!(
        program.constraint_roots().len() == component.n_constraints(),
        "{name}: recorded {} constraints, official component reports {}",
        program.constraint_roots().len(),
        component.n_constraints()
    );
    summary.components += 1;
    summary.constraints += component.n_constraints();
    summary.base_instructions += program.base_insts().len();
    summary.extension_instructions += program.ext_insts().len();
    summary.extension_parameters += sources.len();
    let report = format!(
        "{name}: log={} constraints={} base_insts={} ext_insts={} ext_params={} hash={:016x}",
        eval.log_size(),
        component.n_constraints(),
        program.base_insts().len(),
        program.ext_insts().len(),
        sources.len(),
        program.header().semantic_hash
    );
    let captured = CapturedComponent::new(
        name,
        instance,
        component,
        random_coefficient_offset,
        program,
        sources,
    )?;
    Ok((captured, report))
}
