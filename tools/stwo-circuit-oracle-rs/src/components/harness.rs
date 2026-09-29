//! The evaluator harness of the upstream generated component tests.
//!
//! `air_code_gen/src/circuit/component.rs::gen_tests_module` builds every generated evaluator's
//! test in a fresh `Context` in this exact order:
//!
//! 1. `TestComponentData::from_values`: one `new_var` per trace column; one `new_var` per M31
//!    limb of each interaction QM31 (`at_oods`), then four `new_var`s for the limbs of
//!    `last_row_sum` (`at_prev` of the last four interaction columns); 31 `new_var`s for the bits
//!    of `n_instances = 2^log_height` (LSB first); one `new_var` for `n_instances`;
//! 2. `new_var(random_coeff)`, `new_var(z)`, `new_var(alpha)`;
//! 3. `constant(value)` for each preprocessed column in `external_states` order (`Seq` is keyed
//!    `seq_{log_height}`), then for each public parameter in `public_params` order;
//! 4. `CompositionConstraintAccumulator::new`, `Component::evaluate`;
//! 5. `new_var(claimed_sum)`, `finalize_logup_in_pairs`, `finalize`.
//!
//! In value mode the oracle uses the upstream `TestComponentData` itself. In topology mode it
//! uses [`TopologyComponentData`], which mirrors that allocation order; the caller asserts that
//! both modes produce identical gate lists, which pins the mirror to the upstream harness.

use std::collections::HashMap;

use circuits::context::{Context, Var};
use circuits::ivalue::IValue;
use circuits_stark_verifier::constraint_eval::{
    CircuitEval, ComponentDataTrait, CompositionConstraintAccumulator,
};
use circuits_stark_verifier::proof::InteractionAtOods;
use serde::Serialize;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::QM31;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;

use crate::checkpoint::qm31;

/// Number of `n_instances` bit variables allocated by the upstream test harness.
const N_INSTANCES_BITS: usize = 31;

/// The values fed to one evaluator.
#[derive(Clone, Serialize)]
pub struct HarnessInputs {
    #[serde(serialize_with = "serialize_qm31s")]
    pub base_trace: Vec<QM31>,
    #[serde(serialize_with = "serialize_qm31s")]
    pub interaction_trace: Vec<QM31>,
    /// `(preprocessed column id, value)` in harness order.
    #[serde(serialize_with = "serialize_named_qm31s")]
    pub preprocessed_columns: Vec<(String, QM31)>,
    /// `(public parameter, value)` in harness order.
    #[serde(serialize_with = "serialize_named_m31s")]
    pub public_params: Vec<(String, M31)>,
    #[serde(serialize_with = "serialize_qm31")]
    pub random_coeff: QM31,
    #[serde(serialize_with = "serialize_qm31")]
    pub last_row_sum: QM31,
    #[serde(serialize_with = "serialize_qm31")]
    pub z: QM31,
    #[serde(serialize_with = "serialize_qm31")]
    pub alpha: QM31,
    #[serde(serialize_with = "serialize_qm31")]
    pub claimed_sum: QM31,
    pub log_height: u32,
}

fn serialize_qm31<S: serde::Serializer>(value: &QM31, s: S) -> Result<S::Ok, S::Error> {
    qm31(*value).serialize(s)
}

fn serialize_qm31s<S: serde::Serializer>(values: &[QM31], s: S) -> Result<S::Ok, S::Error> {
    values
        .iter()
        .map(|v| qm31(*v))
        .collect::<Vec<_>>()
        .serialize(s)
}

fn serialize_named_qm31s<S: serde::Serializer>(
    values: &[(String, QM31)],
    s: S,
) -> Result<S::Ok, S::Error> {
    values
        .iter()
        .map(|(name, v)| (name, qm31(*v)))
        .collect::<Vec<_>>()
        .serialize(s)
}

fn serialize_named_m31s<S: serde::Serializer>(
    values: &[(String, M31)],
    s: S,
) -> Result<S::Ok, S::Error> {
    values
        .iter()
        .map(|(name, v)| (name, v.0))
        .collect::<Vec<_>>()
        .serialize(s)
}

/// Topology-mode mirror of `circuits_stark_verifier::test_utils::TestComponentData`.
pub struct TopologyComponentData {
    trace: Vec<Var>,
    interaction_trace: Vec<InteractionAtOods<Var>>,
    n_instances: Var,
    n_instances_bits: Vec<Var>,
}

impl TopologyComponentData {
    pub fn new<V: IValue>(context: &mut Context<V>, inputs: &HarnessInputs) -> Self {
        let trace = inputs
            .base_trace
            .iter()
            .map(|v| context.new_var(V::from_qm31(*v)))
            .collect();
        let mut interaction_trace: Vec<InteractionAtOods<Var>> = inputs
            .interaction_trace
            .iter()
            .flat_map(|v| v.to_m31_array())
            .map(|limb| InteractionAtOods {
                at_oods: context.new_var(V::from_qm31(limb.into())),
                at_prev: None,
            })
            .collect();
        if !interaction_trace.is_empty() {
            let offset = interaction_trace.len() - 4;
            for (i, limb) in inputs.last_row_sum.to_m31_array().into_iter().enumerate() {
                interaction_trace[offset + i].at_prev =
                    Some(context.new_var(V::from_qm31(limb.into())));
            }
        }
        let n_instances = 1usize << inputs.log_height;
        let n_instances_bits = (0..N_INSTANCES_BITS)
            .map(|bit| {
                context.new_var(V::from_qm31(
                    M31::from(((n_instances >> bit) & 1) as u32).into(),
                ))
            })
            .collect();
        let n_instances = context.new_var(V::from_qm31(M31::from(n_instances as u32).into()));
        Self {
            trace,
            interaction_trace,
            n_instances,
            n_instances_bits,
        }
    }
}

impl<V: IValue> ComponentDataTrait<V> for TopologyComponentData {
    fn trace_columns(&self) -> &[Var] {
        &self.trace
    }

    fn interaction_columns(&self) -> &[InteractionAtOods<Var>] {
        &self.interaction_trace
    }

    fn n_instances(&self) -> Var {
        self.n_instances
    }

    fn get_n_instances_bit(&self, _context: &mut Context<V>, bit: usize) -> Var {
        self.n_instances_bits[bit]
    }

    fn max_component_size_bits(&self) -> usize {
        self.n_instances_bits.len()
    }
}

/// Steps 2-5 of the harness; `data` must have been built as step 1 in the same context.
pub fn evaluate<V: IValue>(
    context: &mut Context<V>,
    component: &dyn CircuitEval<V>,
    data: &dyn ComponentDataTrait<V>,
    inputs: &HarnessInputs,
) -> Var {
    evaluate_marked(context, component, data, inputs, &mut |_, _| {})
}

/// The harness stages [`evaluate_marked`] reports, in order.
pub const STAGES: [&str; 3] = ["inputs", "evaluate", "finalize_logup_in_pairs"];

/// [`evaluate`], calling `mark` with the context after each of [`STAGES`]: after step 3 (all
/// harness inputs allocated), after `Component::evaluate`, and after `finalize_logup_in_pairs`
/// (including the `claimed_sum` variable). `CompositionConstraintAccumulator::finalize` adds no
/// gate.
pub fn evaluate_marked<V: IValue>(
    context: &mut Context<V>,
    component: &dyn CircuitEval<V>,
    data: &dyn ComponentDataTrait<V>,
    inputs: &HarnessInputs,
    mark: &mut dyn FnMut(&Context<V>, &'static str),
) -> Var {
    let random_coeff = context.new_var(V::from_qm31(inputs.random_coeff));
    let interaction_elements = [
        context.new_var(V::from_qm31(inputs.z)),
        context.new_var(V::from_qm31(inputs.alpha)),
    ];
    let preprocessed_columns: HashMap<PreProcessedColumnId, Var> = inputs
        .preprocessed_columns
        .iter()
        .map(|(id, value)| {
            (
                PreProcessedColumnId { id: id.clone() },
                context.constant(*value),
            )
        })
        .collect();
    let public_params: HashMap<String, Var> = inputs
        .public_params
        .iter()
        .map(|(name, value)| (name.clone(), context.constant((*value).into())))
        .collect();
    let mut accumulator = CompositionConstraintAccumulator::new(
        context,
        preprocessed_columns,
        public_params,
        random_coeff,
        interaction_elements,
    );
    mark(context, STAGES[0]);
    component.evaluate(context, data, &mut accumulator);
    mark(context, STAGES[1]);
    let claimed_sum = context.new_var(V::from_qm31(inputs.claimed_sum));
    accumulator.finalize_logup_in_pairs(context, data.interaction_columns(), data, claimed_sum);
    mark(context, STAGES[2]);
    accumulator.finalize()
}
