//! Rung R3: every in-circuit evaluator, built in a fresh `Context`.
//!
//! The oracle walks the 83 Cairo slots of `circuit_cairo_verifier::all_components` and the 11
//! circuit components of `circuit_verifier::statement::all_circuit_components`, in their upstream
//! order, and evaluates each through the upstream test harness (see [`harness`]) on the
//! assignment of `outputs/compiled_{casm,circuit}_air/sample_evaluations.json`. For each evaluator
//! it records the gate-list summary, the value digest and the evaluation result, after asserting
//! that value mode and topology mode build identical gate lists and that every generated
//! evaluator reproduces its sample result.
//!
//! Some slots cannot use a sample of their own:
//!
//! - `memory_id_to_big_{1..15}` reuse the `memory_id_to_big` assignment; they differ from slot 0
//!   only in their id offset;
//! - the hand-written evaluators listed in [`SYNTHESIZED`] either have no compiled AIR (circuit
//!   `eq`) or a trace shape different from their compiled AIR (`memory_address_to_id` splits into
//!   16 lanes, `verify_bitwise_xor_12` expands 10-bit tables). Their inputs are synthesized with
//!   the `air_common::utils::random_qm31` labels of `Assignment::new_random_for` and emitted
//!   inline.
//!
//! Upstream pins sample results only for generated evaluators, so the result of a hand-written
//! evaluator is recorded but not asserted.

mod harness;
pub mod statement_trace;

use std::path::Path;

use air_common::utils::random_qm31;
use air_compile::compiled_structs::CompiledAirFn;
use anyhow::{Context as _, Result, bail, ensure};
use circuits::context::Context;
use circuits::ivalue::NoValue;
use circuits_stark_verifier::constraint_eval::CircuitEval;
use circuits_stark_verifier::test_utils::TestComponentData;
use eval_air_fn_constraints::SampleEvaluation;
use indexmap::IndexMap;
use serde::Serialize;
use stwo::core::fields::qm31::QM31;

use crate::checkpoint::{CircuitSummary, Envelope, circuit_summary, qm31, values_sha256};
use crate::compiled_air::{self, AirSource, CAIRO_AIR, CIRCUIT_AIR, CompiledAir};
use crate::upstream::{self, ProvingRoot};
use harness::{HarnessInputs, TopologyComponentData};

/// `ASSIGNMENT_LOG_HEIGHT` of `eval_air_fn_constraints::assignment`.
const DEFAULT_LOG_HEIGHT: u32 = eval_air_fn_constraints::assignment::ASSIGNMENT_LOG_HEIGHT;

/// A hand-written evaluator driven by synthesized inputs.
struct Synthesized {
    air: &'static str,
    name: &'static str,
    /// The external states the evaluator reads, in harness order (`Seq` becomes
    /// `seq_{log_height}`).
    external_states: &'static [&'static str],
    /// The component height; fixed-size evaluators assert their own.
    log_height: u32,
}

/// Every hand-written evaluator the compiled-AIR samples cannot drive, with the preprocessed
/// columns it reads (`crates/{cairo_verifier,circuit_verifier}/src/components/*.rs`).
const SYNTHESIZED: [Synthesized; 4] = [
    Synthesized {
        air: "cairo",
        name: "memory_address_to_id",
        external_states: &["Seq"],
        log_height: DEFAULT_LOG_HEIGHT,
    },
    Synthesized {
        air: "cairo",
        name: "verify_bitwise_xor_12",
        external_states: &["bitwise_xor_10_0", "bitwise_xor_10_1", "bitwise_xor_10_2"],
        log_height: 20,
    },
    Synthesized {
        air: "circuit",
        name: "eq",
        external_states: &["eq_in0_address", "eq_in1_address"],
        log_height: DEFAULT_LOG_HEIGHT,
    },
    Synthesized {
        air: "circuit",
        name: "verify_bitwise_xor_12",
        external_states: &["bitwise_xor_10_0", "bitwise_xor_10_1", "bitwise_xor_10_2"],
        log_height: 20,
    },
];

fn synthesized(air: &AirSource, name: &str) -> Option<&'static Synthesized> {
    SYNTHESIZED
        .iter()
        .find(|entry| entry.air == air.label && entry.name == name)
}

/// The compiled-AIR name of an evaluator slot.
fn air_fn_name(air: &AirSource, slot_name: &str) -> String {
    match (air.label, slot_name) {
        ("cairo", name) if name.starts_with("memory_id_to_big") => "memory_id_to_big".into(),
        ("circuit", "qm31_ops") => "qm_31_ops".into(),
        (_, name) => name.into(),
    }
}

#[derive(Serialize)]
pub struct RelationUseRecord {
    pub relation_id: &'static str,
    pub uses: u64,
}

#[derive(Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum AssignmentRecord {
    /// The assignment of `sample_evaluations.json[key]`, with the harness orderings.
    SampleEvaluations {
        key: String,
        log_height: u32,
        preprocessed_columns: Vec<String>,
        public_params: Vec<String>,
    },
    /// Inputs synthesized with `random_qm31` labels, emitted in full.
    Synthesized { inputs: HarnessInputs },
}

#[derive(Serialize)]
pub struct EvaluatorRecord {
    pub air: &'static str,
    pub slot: usize,
    pub name: &'static str,
    pub evaluator_name: String,
    pub trace_columns: usize,
    pub interaction_columns: usize,
    pub relation_uses_per_row: Vec<RelationUseRecord>,
    pub hand_written: bool,
    pub assignment: AssignmentRecord,
    pub result: [u32; 4],
    /// The asserted `result` of the sample evaluation: set for every generated evaluator,
    /// `null` for hand-written ones.
    pub expected_result: Option<[u32; 4]>,
    pub circuit: CircuitSummary,
    pub values_sha256: String,
}

#[derive(Serialize)]
pub struct ComponentsBody {
    pub cairo_slots: Vec<&'static str>,
    pub circuit_components: Vec<&'static str>,
    pub evaluators: Vec<EvaluatorRecord>,
}

fn sample_inputs(air_fn: &CompiledAirFn, sample: &SampleEvaluation) -> Result<HarnessInputs> {
    let assignment = &sample.assignment;
    let environment = &assignment.environment;
    let preprocessed_columns = air_fn
        .external_states
        .iter()
        .map(|state| {
            let value = *environment
                .external_states
                .get(state)
                .with_context(|| format!("{}: no sample value for {state}", air_fn.name))?;
            let id = if state == "Seq" {
                format!("seq_{}", assignment.log_height)
            } else {
                state.clone()
            };
            Ok((id, value))
        })
        .collect::<Result<_>>()?;
    let public_params = air_fn
        .public_params
        .iter()
        .map(|param| {
            let value = *environment
                .public_params
                .get(param)
                .with_context(|| format!("{}: no sample value for {param}", air_fn.name))?;
            Ok((param.clone(), value))
        })
        .collect::<Result<_>>()?;
    Ok(HarnessInputs {
        base_trace: assignment.base_trace.clone(),
        interaction_trace: assignment.interaction_trace.clone(),
        preprocessed_columns,
        public_params,
        random_coeff: assignment.random_coeff,
        last_row_sum: assignment.last_row_sum,
        z: assignment.common_lookup_elements.z,
        alpha: assignment.common_lookup_elements.alpha,
        claimed_sum: assignment.claimed_sum,
        log_height: assignment.log_height,
    })
}

/// Inputs labelled as `Assignment::new_random_for` labels them.
fn synthesized_inputs(component: &dyn CircuitEval<QM31>, entry: &Synthesized) -> HarnessInputs {
    let log_height = entry.log_height;
    HarnessInputs {
        base_trace: (0..component.trace_columns())
            .map(|i| random_qm31(&format!("base_{i}")))
            .collect(),
        interaction_trace: (0..component.interaction_columns() / 4)
            .map(|i| random_qm31(&format!("interaction_{i}")))
            .collect(),
        preprocessed_columns: entry
            .external_states
            .iter()
            .map(|state| {
                let id = if *state == "Seq" {
                    format!("seq_{log_height}")
                } else {
                    (*state).to_owned()
                };
                (id, random_qm31(state))
            })
            .collect(),
        public_params: Vec::new(),
        random_coeff: random_qm31("random_coeff"),
        last_row_sum: random_qm31("last_row_sum"),
        z: random_qm31("common_z"),
        alpha: random_qm31("common_alpha"),
        claimed_sum: random_qm31("claimed_sum"),
        log_height,
    }
}

/// Selects the harness inputs of a slot and, for generated evaluators, the asserted result.
fn slot_inputs(
    air: &AirSource,
    name: &str,
    component: &dyn CircuitEval<QM31>,
    compiled: &CompiledAir,
) -> Result<(HarnessInputs, AssignmentRecord, Option<[u32; 4]>)> {
    if let Some(entry) = synthesized(air, name) {
        let inputs = synthesized_inputs(component, entry);
        return Ok((
            inputs.clone(),
            AssignmentRecord::Synthesized { inputs },
            None,
        ));
    }
    let key = air_fn_name(air, name);
    let (Some(air_fn), Some(sample)) = (compiled.functions.get(&key), compiled.samples.get(&key))
    else {
        bail!(
            "{}: evaluator {name} has no compiled AIR and sample {key}",
            air.label
        );
    };
    let inputs = sample_inputs(air_fn, sample)?;
    ensure!(
        inputs.base_trace.len() == component.trace_columns()
            && 4 * inputs.interaction_trace.len() == component.interaction_columns(),
        "{}: sample {key} does not have the shape of evaluator {name}",
        air.label
    );
    let assignment = AssignmentRecord::SampleEvaluations {
        key: key.clone(),
        log_height: inputs.log_height,
        preprocessed_columns: inputs
            .preprocessed_columns
            .iter()
            .map(|(id, _)| id.clone())
            .collect(),
        public_params: inputs
            .public_params
            .iter()
            .map(|(p, _)| p.clone())
            .collect(),
    };
    let expected = compiled_air::is_generated(&key).then(|| qm31(sample.result));
    Ok((inputs, assignment, expected))
}

fn evaluate_topology(
    component: &dyn CircuitEval<NoValue>,
    inputs: &HarnessInputs,
) -> (usize, CircuitSummary) {
    let mut context = Context::<NoValue>::default();
    let data = TopologyComponentData::new(&mut context, inputs);
    let result = harness::evaluate(&mut context, component, &data, inputs);
    (result.idx, circuit_summary(&context.circuit))
}

fn evaluator_record(
    air: &AirSource,
    slot: usize,
    name: &'static str,
    component: &dyn CircuitEval<QM31>,
    topology: &dyn CircuitEval<NoValue>,
    compiled: &CompiledAir,
) -> Result<EvaluatorRecord> {
    let air_fn = air_fn_name(air, name);
    let hand_written =
        !compiled.functions.contains_key(&air_fn) || !compiled_air::is_generated(&air_fn);
    let (inputs, assignment, expected_result) = slot_inputs(air, name, component, compiled)?;
    ensure!(
        hand_written || expected_result.is_some(),
        "{}: generated evaluator {name} has no sample result to assert",
        air.label
    );

    let mut context = Context::<QM31>::default();
    context.enable_assert_eq_on_eval();
    let data = TestComponentData::from_values(
        &mut context,
        &inputs.base_trace,
        &inputs.interaction_trace,
        inputs.last_row_sum,
        1 << inputs.log_height,
    );
    let result = harness::evaluate(&mut context, component, &data, &inputs);
    let value = qm31(context.get(result));
    let circuit = circuit_summary(&context.circuit);

    let (topology_result, topology_circuit) = evaluate_topology(topology, &inputs);
    ensure!(
        topology_result == result.idx,
        "{name}: topology result variable differs"
    );
    ensure!(
        topology_circuit == circuit,
        "{name}: topology gate lists differ"
    );
    if let Some(expected) = expected_result {
        ensure!(
            value == expected,
            "{name}: result differs from the sample evaluation"
        );
    }

    Ok(EvaluatorRecord {
        air: air.label,
        slot,
        name,
        evaluator_name: component.name(),
        trace_columns: component.trace_columns(),
        interaction_columns: component.interaction_columns(),
        relation_uses_per_row: component
            .relation_uses_per_row()
            .iter()
            .map(|r| RelationUseRecord {
                relation_id: r.relation_id,
                uses: r.uses,
            })
            .collect(),
        hand_written,
        assignment,
        result: value,
        expected_result,
        values_sha256: values_sha256(context.values()),
        circuit,
    })
}

fn evaluate_all(
    air: &AirSource,
    components: &IndexMap<&'static str, Box<dyn CircuitEval<QM31>>>,
    topology: &IndexMap<&'static str, Box<dyn CircuitEval<NoValue>>>,
    compiled: &CompiledAir,
) -> Result<Vec<EvaluatorRecord>> {
    ensure!(
        components.keys().eq(topology.keys()),
        "{}: value and topology component lists differ",
        air.label
    );
    let records = components
        .iter()
        .zip(topology.values())
        .enumerate()
        .map(|(slot, ((name, component), topology))| {
            evaluator_record(
                air,
                slot,
                name,
                component.as_ref(),
                topology.as_ref(),
                compiled,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    for key in compiled.samples.keys() {
        let used = records.iter().any(|record| {
            matches!(&record.assignment, AssignmentRecord::SampleEvaluations { key: k, .. } if k == key)
        });
        ensure!(
            used || synthesized(air, key).is_some(),
            "{}: sample evaluation {key} is not used by any evaluator",
            air.label
        );
    }
    Ok(records)
}

pub fn run(proving_root: &Path) -> Result<Envelope<ComponentsBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let cairo_air = compiled_air::load(&mut root, &CAIRO_AIR)?;
    let circuit_air = compiled_air::load(&mut root, &CIRCUIT_AIR)?;
    let inputs = root.finish(upstream::PINNED_COMPILED_AIR_SHA256)?;

    let cairo = circuit_cairo_verifier::all_components::all_components::<QM31>();
    let circuit = circuit_verifier::statement::all_circuit_components::<QM31>();
    let mut evaluators = evaluate_all(
        &CAIRO_AIR,
        &cairo,
        &circuit_cairo_verifier::all_components::all_components::<NoValue>(),
        &cairo_air,
    )?;
    evaluators.extend(evaluate_all(
        &CIRCUIT_AIR,
        &circuit,
        &circuit_verifier::statement::all_circuit_components::<NoValue>(),
        &circuit_air,
    )?);

    Ok(Envelope::new(
        "r3",
        "components",
        inputs,
        ComponentsBody {
            cairo_slots: cairo.keys().copied().collect(),
            circuit_components: circuit.keys().copied().collect(),
            evaluators,
        },
    ))
}
