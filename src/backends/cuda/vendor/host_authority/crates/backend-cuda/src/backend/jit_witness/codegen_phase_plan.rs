//! Deterministic two-phase plan for the witness codegen experiment.
//!
//! A cut is legal only between complete bytecode instructions with no pending
//! `DeduceArg` bank. Values crossing it are sourced, in order of preference,
//! from immutable constants/inputs, a globally unique final output stored at its
//! last prefix use, or a dense word-major scratch slot. This plan is codegen-only
//! until its interpreter differential and exact ptxas resource gates pass.

use std::collections::{BTreeMap, BTreeSet};

use super::schedule::{OutputSchedule, OutputTarget, ProgramAnalysis, StoreEvent};
use super::{WitnessOp, WitnessProgram, WITNESS_CODEGEN_VERSION};

pub const PHASE_CODEGEN_VERSION: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum PhaseOutputTarget {
    Column(u32),
    LookupWord(u32),
    SubWord(u32),
}

impl From<OutputTarget> for PhaseOutputTarget {
    fn from(value: OutputTarget) -> Self {
        match value {
            OutputTarget::Column(index) => Self::Column(index),
            OutputTarget::LookupWord(index) => Self::LookupWord(index),
            OutputTarget::SubWord(index) => Self::SubWord(index),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundarySource {
    Constant(u32),
    Input(u32),
    Output(PhaseOutputTarget),
    Scratch {
        slot: u32,
        transport_anchor: TransportAnchor,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum TransportAnchor {
    AfterInstruction(usize),
    AfterDeduceArguments(usize),
    AfterDeduceRegister {
        instruction: usize,
        register: usize,
        bank_offset: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryValue {
    pub register: u32,
    pub first_suffix_instruction: usize,
    pub source: BoundarySource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MovedStore {
    pub register: u32,
    pub target: PhaseOutputTarget,
    pub original_anchor_instruction: usize,
    pub transport_anchor: TransportAnchor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPhasePlan {
    pub parent_semantic_hash: u64,
    pub cut_instruction: usize,
    pub after_deduce_ordinal: Option<usize>,
    pub boundary: Vec<BoundaryValue>,
    pub moved_stores: Vec<MovedStore>,
    pub scratch_words_per_row: u32,
    pub plan_hash: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhasePlanError {
    MalformedProgram,
    MissingDeduceOrdinal(usize),
    IllegalCut(usize),
}

impl WitnessPhasePlan {
    pub fn after_deduce(
        program: &WitnessProgram,
        deduce_ordinal: usize,
    ) -> Result<Self, PhasePlanError> {
        let mut seen = 0usize;
        let mut cut = None;
        for (instruction, inst) in program.insts.iter().enumerate() {
            if WitnessOp::from_raw(inst.op) == Some(WitnessOp::DeduceCall) {
                if seen == deduce_ordinal {
                    cut = Some(instruction + 1);
                    break;
                }
                seen += 1;
            }
        }
        let cut = cut.ok_or(PhasePlanError::MissingDeduceOrdinal(deduce_ordinal))?;
        let plan = Self::at_cut(program, cut)?;
        (plan.after_deduce_ordinal == Some(deduce_ordinal))
            .then_some(plan)
            .ok_or(PhasePlanError::MissingDeduceOrdinal(deduce_ordinal))
    }

    pub fn at_cut(
        program: &WitnessProgram,
        cut_instruction: usize,
    ) -> Result<Self, PhasePlanError> {
        let analysis = OutputSchedule::analyze(program).ok_or(PhasePlanError::MalformedProgram)?;
        if !analysis
            .legal_cuts
            .get(cut_instruction)
            .copied()
            .unwrap_or(false)
        {
            return Err(PhasePlanError::IllegalCut(cut_instruction));
        }
        let after_deduce_ordinal = cut_instruction.checked_sub(1).and_then(|previous| {
            (WitnessOp::from_raw(program.insts[previous].op) == Some(WitnessOp::DeduceCall)).then(
                || {
                    program.insts[..=previous]
                        .iter()
                        .filter(|inst| WitnessOp::from_raw(inst.op) == Some(WitnessOp::DeduceCall))
                        .count()
                        - 1
                },
            )
        });

        let stores_by_target = stores_by_target(&analysis);
        let mut used_output_targets = BTreeSet::new();
        let mut boundary = Vec::new();
        let mut moved_stores = Vec::new();
        let mut next_scratch_slot = 0u32;

        for register in 0..program.n_regs as usize {
            let Some(definition) = analysis.definitions[register] else {
                continue;
            };
            if definition.instruction >= cut_instruction {
                continue;
            }
            let future_uses = suffix_uses(&analysis, register, cut_instruction, None);
            let Some(&first_use) = future_uses.first() else {
                continue;
            };

            let defining_inst = &program.insts[definition.instruction];
            let source = match WitnessOp::from_raw(defining_inst.op) {
                Some(WitnessOp::Const) => BoundarySource::Constant(defining_inst.imm),
                Some(WitnessOp::Input) => BoundarySource::Input(defining_inst.a),
                _ => {
                    let transport_anchor =
                        prefix_transport_anchor(&analysis, register as u32, cut_instruction)
                            .ok_or(PhasePlanError::MalformedProgram)?;
                    let movable = unique_future_store(
                        &analysis,
                        &stores_by_target,
                        register as u32,
                        cut_instruction,
                    );
                    if let Some(event) = movable {
                        let target = PhaseOutputTarget::from(event.output.target());
                        let uses_without_store =
                            suffix_uses(&analysis, register, cut_instruction, Some(event));
                        if !used_output_targets.insert(target) {
                            let slot = next_scratch_slot;
                            next_scratch_slot += 1;
                            BoundarySource::Scratch {
                                slot,
                                transport_anchor,
                            }
                        } else {
                            // Global target uniqueness proves last-writer-at-cut,
                            // injectivity, and no overwrite before lazy first use.
                            moved_stores.push(MovedStore {
                                register: register as u32,
                                target,
                                original_anchor_instruction: event.anchor.rank().0,
                                transport_anchor,
                            });
                            if let Some(&first_use_without_store) = uses_without_store.first() {
                                boundary.push(BoundaryValue {
                                    register: register as u32,
                                    first_suffix_instruction: first_use_without_store,
                                    source: BoundarySource::Output(target),
                                });
                            }
                            continue;
                        }
                    } else {
                        let slot = next_scratch_slot;
                        next_scratch_slot += 1;
                        BoundarySource::Scratch {
                            slot,
                            transport_anchor,
                        }
                    }
                }
            };
            boundary.push(BoundaryValue {
                register: register as u32,
                first_suffix_instruction: first_use,
                source,
            });
        }

        boundary.sort_by_key(|value| value.register);
        moved_stores.sort_by_key(|store| store.register);
        let plan_hash = phase_plan_hash(
            program.semantic_hash(),
            cut_instruction,
            &boundary,
            &moved_stores,
        );
        Ok(Self {
            parent_semantic_hash: program.semantic_hash(),
            cut_instruction,
            after_deduce_ordinal,
            boundary,
            moved_stores,
            scratch_words_per_row: next_scratch_slot,
            plan_hash,
        })
    }

    pub fn phase_cache_key(&self, ordinal: u32) -> u64 {
        fnv64(
            self.parent_semantic_hash
                .to_le_bytes()
                .into_iter()
                .chain(WITNESS_CODEGEN_VERSION.to_le_bytes())
                .chain(PHASE_CODEGEN_VERSION.to_le_bytes())
                .chain(self.plan_hash.to_le_bytes())
                .chain(ordinal.to_le_bytes()),
        )
    }

    pub fn phase_kernel_name(&self, ordinal: u32) -> String {
        format!(
            "stwo_jit_witness_{:016x}_plan_{:016x}_phase_{ordinal}",
            self.parent_semantic_hash, self.plan_hash
        )
    }
}

fn stores_by_target(analysis: &ProgramAnalysis) -> BTreeMap<OutputTarget, Vec<StoreEvent>> {
    let mut result: BTreeMap<OutputTarget, Vec<StoreEvent>> = BTreeMap::new();
    for event in &analysis.stores {
        result
            .entry(event.output.target())
            .or_default()
            .push(*event);
    }
    result
}

fn unique_future_store(
    analysis: &ProgramAnalysis,
    stores_by_target: &BTreeMap<OutputTarget, Vec<StoreEvent>>,
    register: u32,
    cut: usize,
) -> Option<StoreEvent> {
    analysis.stores.iter().copied().find(|event| {
        event.output.register == register
            && event.anchor.rank().0 >= cut
            && stores_by_target
                .get(&event.output.target())
                .is_some_and(|events| events.len() == 1)
    })
}

fn suffix_uses(
    analysis: &ProgramAnalysis,
    register: usize,
    cut: usize,
    suppressed_store: Option<StoreEvent>,
) -> Vec<usize> {
    let mut uses = analysis.computational_uses[register]
        .iter()
        .copied()
        .filter(|&instruction| instruction >= cut)
        .collect::<Vec<_>>();
    uses.extend(
        analysis
            .stores
            .iter()
            .filter(|event| {
                event.output.register as usize == register
                    && event.anchor.rank().0 >= cut
                    && Some(**event) != suppressed_store
            })
            .map(|event| event.anchor.rank().0),
    );
    uses.sort_unstable();
    uses.dedup();
    uses
}

fn prefix_transport_anchor(
    analysis: &ProgramAnalysis,
    register: u32,
    cut: usize,
) -> Option<TransportAnchor> {
    let register = register as usize;
    let last_prefix_use = analysis
        .computational_uses
        .get(register)?
        .iter()
        .copied()
        .take_while(|&instruction| instruction < cut)
        .last();
    let anchor = if let Some(instruction) = last_prefix_use {
        if analysis.deduce_argument_uses[register].contains(&instruction) {
            TransportAnchor::AfterDeduceArguments(instruction)
        } else {
            TransportAnchor::AfterInstruction(instruction)
        }
    } else {
        let definition = analysis.definitions.get(register)?.as_ref()?;
        match definition.deduce_bank_offset {
            Some(bank_offset) => TransportAnchor::AfterDeduceRegister {
                instruction: definition.instruction,
                register,
                bank_offset,
            },
            None => TransportAnchor::AfterInstruction(definition.instruction),
        }
    };
    (anchor.instruction() < cut).then_some(anchor)
}

impl TransportAnchor {
    fn instruction(self) -> usize {
        match self {
            Self::AfterInstruction(instruction) | Self::AfterDeduceArguments(instruction) => {
                instruction
            }
            Self::AfterDeduceRegister { instruction, .. } => instruction,
        }
    }
}

fn phase_plan_hash(
    semantic_hash: u64,
    cut: usize,
    boundary: &[BoundaryValue],
    stores: &[MovedStore],
) -> u64 {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&semantic_hash.to_le_bytes());
    bytes.extend_from_slice(&(cut as u64).to_le_bytes());
    for value in boundary {
        bytes.extend_from_slice(&value.register.to_le_bytes());
        bytes.extend_from_slice(&(value.first_suffix_instruction as u64).to_le_bytes());
        match value.source {
            BoundarySource::Constant(value) => {
                bytes.push(0);
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            BoundarySource::Input(index) => {
                bytes.push(1);
                bytes.extend_from_slice(&index.to_le_bytes());
            }
            BoundarySource::Output(target) => {
                bytes.push(2);
                encode_target(target, &mut bytes);
            }
            BoundarySource::Scratch {
                slot,
                transport_anchor,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&slot.to_le_bytes());
                encode_anchor(transport_anchor, &mut bytes);
            }
        }
    }
    for store in stores {
        bytes.extend_from_slice(&store.register.to_le_bytes());
        encode_target(store.target, &mut bytes);
        bytes.extend_from_slice(&(store.original_anchor_instruction as u64).to_le_bytes());
        encode_anchor(store.transport_anchor, &mut bytes);
    }
    fnv64(bytes)
}

fn encode_anchor(anchor: TransportAnchor, bytes: &mut Vec<u8>) {
    match anchor {
        TransportAnchor::AfterInstruction(instruction) => {
            bytes.push(0);
            bytes.extend_from_slice(&(instruction as u64).to_le_bytes());
        }
        TransportAnchor::AfterDeduceArguments(instruction) => {
            bytes.push(1);
            bytes.extend_from_slice(&(instruction as u64).to_le_bytes());
        }
        TransportAnchor::AfterDeduceRegister {
            instruction,
            register,
            bank_offset,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&(instruction as u64).to_le_bytes());
            bytes.extend_from_slice(&(register as u64).to_le_bytes());
            bytes.extend_from_slice(&(bank_offset as u64).to_le_bytes());
        }
    }
}

fn encode_target(target: PhaseOutputTarget, bytes: &mut Vec<u8>) {
    let (tag, index) = match target {
        PhaseOutputTarget::Column(index) => (0, index),
        PhaseOutputTarget::LookupWord(index) => (1, index),
        PhaseOutputTarget::SubWord(index) => (2, index),
    };
    bytes.push(tag);
    bytes.extend_from_slice(&index.to_le_bytes());
}

fn fnv64(bytes: impl IntoIterator<Item = u8>) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::super::super::recording::WitnessRecorder;
    use super::*;

    #[test]
    fn source_precedence_is_constant_then_input_then_unique_output_then_scratch() {
        let mut recorder = WitnessRecorder::new("phase_precedence");
        let input = recorder.input(0);
        let constant = recorder.constant(7);
        let _sum = recorder.m31_add(input, constant);
        let cut = recorder.finish().insts.len();

        // Re-record with a suffix because finish consumes the recorder.
        let mut recorder = WitnessRecorder::new("phase_precedence");
        let input = recorder.input(0);
        let constant = recorder.constant(7);
        let sum = recorder.m31_add(input, constant);
        recorder.col_write(0, sum);
        let product = recorder.m31_mul(sum, input);
        let final_value = recorder.m31_add(product, constant);
        recorder.col_write(1, final_value);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::at_cut(&program, cut).unwrap();

        assert!(plan.boundary.iter().any(|value| {
            value.register == u32::from(input.0) && value.source == BoundarySource::Input(0)
        }));
        assert!(plan.boundary.iter().any(|value| {
            value.register == u32::from(constant.0) && value.source == BoundarySource::Constant(7)
        }));
        assert!(plan.boundary.iter().any(|value| {
            value.register == u32::from(sum.0)
                && value.source == BoundarySource::Output(PhaseOutputTarget::Column(0))
        }));
        assert_eq!(plan.scratch_words_per_row, 0);
    }

    #[test]
    fn duplicate_target_before_first_suffix_use_forces_scratch() {
        let mut recorder = WitnessRecorder::new("phase_duplicate_target");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let first = recorder.m31_add(a, b);
        let cut = 3;
        recorder.col_write(0, first);
        let overwrite = recorder.m31_sub(a, b);
        recorder.col_write(0, overwrite);
        let late = recorder.m31_mul(first, overwrite);
        recorder.col_write(1, late);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::at_cut(&program, cut).unwrap();
        let first_boundary = plan
            .boundary
            .iter()
            .find(|value| value.register == u32::from(first.0))
            .unwrap();
        assert!(matches!(
            first_boundary.source,
            BoundarySource::Scratch { .. }
        ));
    }

    #[test]
    fn phase_identity_binds_cut_layout_and_ordinal() {
        let mut recorder = WitnessRecorder::new("phase_identity");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let c = recorder.m31_add(a, b);
        let d = recorder.m31_mul(c, b);
        recorder.col_write(0, d);
        let program = recorder.finish();
        let first = WitnessPhasePlan::at_cut(&program, 2).unwrap();
        let second = WitnessPhasePlan::at_cut(&program, 3).unwrap();
        assert_ne!(first.plan_hash, second.plan_hash);
        assert_ne!(first.phase_cache_key(0), first.phase_cache_key(1));
        assert_ne!(first.phase_cache_key(0), second.phase_cache_key(0));
        let key = first.phase_cache_key(0);
        assert_ne!(key, fnv64(first.parent_semantic_hash.to_le_bytes()));

        let mut altered_boundary = second.boundary.clone();
        let BoundarySource::Scratch {
            transport_anchor, ..
        } = &mut altered_boundary
            .iter_mut()
            .find(|value| matches!(value.source, BoundarySource::Scratch { .. }))
            .unwrap()
            .source
        else {
            panic!("expected scratch crossing")
        };
        *transport_anchor = TransportAnchor::AfterInstruction(0);
        assert_ne!(
            second.plan_hash,
            phase_plan_hash(
                second.parent_semantic_hash,
                second.cut_instruction,
                &altered_boundary,
                &second.moved_stores,
            )
        );
    }
}
