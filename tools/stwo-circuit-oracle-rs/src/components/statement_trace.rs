//! Rung R3 `statement-trace`: where inside an evaluator a gate list first diverges.
//!
//! `components` pins each evaluator's whole gate list; this checkpoint localises a mismatch. Each
//! evaluator of [`super::run`] is rebuilt in topology mode (`NoValue`) on the same harness inputs,
//! and the harness reports the context after each of its [`harness::STAGES`]. For every stage
//! after `inputs`, and every gate kind the stage appended to, the checkpoint records the appended
//! gates with variables renumbered relative to the evaluator: `rel = var - base`, where `base` is
//! `n_vars` after the harness inputs (so harness inputs are negative), each written as the `i32`
//! two's complement little-endian `u32`. Gates are recorded in the per-kind order upstream appends
//! them, with the field order of `checkpoint::circuit_summary`.
//!
//! ```text
//! kind digest   := SHA-256(DOMAIN || kind || 0x00 || count u64 || records)
//! window digest := SHA-256(DOMAIN || kind || 0x00 || window u32 || records of gates
//!                          [128 * window, 128 * window + 128))
//! ```
//!
//! A reader compares kind digests first and then windows, which names the first differing run of
//! at most 128 gates of one kind in one harness stage.

use std::path::Path;

use anyhow::Result;
use circuits::context::Context;
use circuits::ivalue::NoValue;
use circuits_stark_verifier::constraint_eval::CircuitEval;
use indexmap::IndexMap;
use serde::Serialize;
use sha2::{Digest, Sha256};
use stwo::core::fields::qm31::QM31;

use super::harness::{self, HarnessInputs, TopologyComponentData};
use super::{AssignmentRecord, slot_inputs};
use crate::checkpoint::{Envelope, GATE_KINDS, Gate, gate_counts, visit_gates};
use crate::compiled_air::{self, AirSource, CAIRO_AIR, CIRCUIT_AIR, CompiledAir};
use crate::upstream::{self, ProvingRoot};

const DOMAIN: &[u8] = b"STWO_CIRCUIT_STATEMENT_TRACE_V1\0";
pub const WINDOW: usize = 128;

#[derive(Serialize)]
pub struct KindTrace {
    pub kind: &'static str,
    pub count: u64,
    pub sha256: String,
    pub windows: Vec<String>,
}

#[derive(Serialize)]
pub struct StageTrace {
    pub stage: &'static str,
    /// `n_vars` after the stage, relative to `base`.
    pub n_vars: u64,
    pub kinds: Vec<KindTrace>,
}

#[derive(Serialize)]
pub struct EvaluatorTrace {
    pub air: &'static str,
    pub slot: usize,
    pub name: &'static str,
    /// The sample key or `synthesized`, as in `components`.
    pub assignment: String,
    pub base: u64,
    pub stages: Vec<StageTrace>,
}

#[derive(Serialize)]
pub struct StatementTraceBody {
    pub window: usize,
    pub evaluators: Vec<EvaluatorTrace>,
}

struct KindDigest {
    kind: &'static str,
    count: u64,
    records: Sha256,
    window: Option<Sha256>,
    windows: Vec<String>,
}

impl KindDigest {
    fn new(kind: &'static str) -> Self {
        Self {
            kind,
            count: 0,
            records: Sha256::new(),
            window: None,
            windows: Vec::new(),
        }
    }

    fn header(&self) -> Sha256 {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        hasher.update(self.kind.as_bytes());
        hasher.update([0u8]);
        hasher
    }

    fn update(&mut self, bytes: &[u8]) {
        self.records.update(bytes);
        self.window.as_mut().expect("open window").update(bytes);
    }

    fn gate(&mut self, gate: Gate<'_>, base: usize) {
        if self.count as usize % WINDOW == 0 {
            self.close_window();
            let mut window = self.header();
            window.update(((self.count as usize / WINDOW) as u32).to_le_bytes());
            self.window = Some(window);
        }
        self.count += 1;
        let relative = |var: usize| ((var as i64 - base as i64) as i32).to_le_bytes();
        match gate {
            Gate::Fields(fields) => fields.iter().for_each(|&var| self.update(&relative(var))),
            Gate::Lists(inputs, outputs) => {
                for list in [inputs, outputs] {
                    self.update(&(list.len() as u32).to_le_bytes());
                    list.iter().for_each(|&var| self.update(&relative(var)));
                }
            }
        }
    }

    fn close_window(&mut self) {
        if let Some(window) = self.window.take() {
            self.windows.push(hex::encode(window.finalize()));
        }
    }

    fn finish(mut self) -> Option<KindTrace> {
        self.close_window();
        if self.count == 0 {
            return None;
        }
        let mut outer = self.header();
        outer.update(self.count.to_le_bytes());
        outer.update(self.records.finalize());
        Some(KindTrace {
            kind: self.kind,
            count: self.count,
            sha256: hex::encode(outer.finalize()),
            windows: self.windows,
        })
    }
}

fn trace(component: &dyn CircuitEval<NoValue>, inputs: &HarnessInputs) -> (u64, Vec<StageTrace>) {
    let mut context = Context::<NoValue>::default();
    let data = TopologyComponentData::new(&mut context, inputs);
    let mut marks = Vec::new();
    harness::evaluate_marked(&mut context, component, &data, inputs, &mut |context, stage| {
        marks.push((stage, gate_counts(&context.circuit), context.circuit.n_vars));
    });
    let circuit = &context.circuit;
    let (_, _, base) = marks[0];
    let stages = marks
        .windows(2)
        .map(|pair| {
            let [(_, start, _), (stage, end, n_vars)] = pair else {
                unreachable!()
            };
            let mut digests = GATE_KINDS.map(KindDigest::new);
            let mut seen = start.map(|_| 0usize);
            visit_gates(circuit, *start, |kind, gate| {
                if start[kind] + seen[kind] < end[kind] {
                    seen[kind] += 1;
                    digests[kind].gate(gate, base);
                }
            });
            StageTrace {
                stage,
                n_vars: (n_vars - base) as u64,
                kinds: digests.into_iter().filter_map(KindDigest::finish).collect(),
            }
        })
        .collect();
    (base as u64, stages)
}

fn evaluators(
    air: &AirSource,
    components: &IndexMap<&'static str, Box<dyn CircuitEval<QM31>>>,
    topology: &IndexMap<&'static str, Box<dyn CircuitEval<NoValue>>>,
    compiled: &CompiledAir,
) -> Result<Vec<EvaluatorTrace>> {
    components
        .iter()
        .zip(topology.values())
        .enumerate()
        .map(|(slot, ((name, component), topology))| {
            let (inputs, assignment, _) = slot_inputs(air, name, component.as_ref(), compiled)?;
            let (base, stages) = trace(topology.as_ref(), &inputs);
            Ok(EvaluatorTrace {
                air: air.label,
                slot,
                name,
                assignment: match assignment {
                    AssignmentRecord::SampleEvaluations { key, .. } => key,
                    AssignmentRecord::Synthesized { .. } => "synthesized".into(),
                },
                base,
                stages,
            })
        })
        .collect()
}

pub fn run(proving_root: &Path) -> Result<Envelope<StatementTraceBody>> {
    let mut root = ProvingRoot::open(proving_root)?;
    let cairo_air = compiled_air::load(&mut root, &CAIRO_AIR)?;
    let circuit_air = compiled_air::load(&mut root, &CIRCUIT_AIR)?;
    let inputs = root.finish(upstream::PINNED_COMPILED_AIR_SHA256)?;

    let mut traces = evaluators(
        &CAIRO_AIR,
        &circuit_cairo_verifier::all_components::all_components::<QM31>(),
        &circuit_cairo_verifier::all_components::all_components::<NoValue>(),
        &cairo_air,
    )?;
    traces.extend(evaluators(
        &CIRCUIT_AIR,
        &circuit_verifier::statement::all_circuit_components::<QM31>(),
        &circuit_verifier::statement::all_circuit_components::<NoValue>(),
        &circuit_air,
    )?);
    Ok(Envelope::new(
        "r3",
        "statement-trace",
        inputs,
        StatementTraceBody {
            window: WINDOW,
            evaluators: traces,
        },
    ))
}
