//! CUDA emission for an experimental two-phase witness plan.
//!
//! The production monolithic emitter remains byte-for-byte unchanged. This module
//! asks it for an instruction-marked source, slices only at a validated plan cut,
//! anchors transports at their last legal phase-0 use, then lazily reconstructs
//! each crossing SSA value immediately before its first phase-1 use.

use std::collections::BTreeMap;

use super::phase_plan::{BoundarySource, PhaseOutputTarget, TransportAnchor, WitnessPhasePlan};
use super::{compile_witness_to_marked_cuda_source, WitnessProgram};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmittedWitnessPhase {
    pub ordinal: u32,
    pub kernel_name: String,
    pub cache_key: u64,
    pub source: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmittedWitnessPhaseProgram {
    pub parent_semantic_hash: u64,
    pub plan_hash: u64,
    pub scratch_words_per_row: u32,
    pub phases: Vec<EmittedWitnessPhase>,
}

impl EmittedWitnessPhaseProgram {
    pub fn scratch_words(&self, row_count: u32) -> Option<usize> {
        (self.scratch_words_per_row as usize).checked_mul(row_count as usize)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PhaseEmissionError {
    PlanProgramMismatch,
    MarkedSourceUnavailable,
    MalformedMarkedSource,
    MissingInstructionMarker(usize),
    TransportStoreNotFound {
        register: u32,
    },
    MovedStoreNotFound {
        register: u32,
        target: PhaseOutputTarget,
    },
}

pub fn compile_witness_to_phase_sources(
    program: &WitnessProgram,
    plan: &WitnessPhasePlan,
) -> Result<EmittedWitnessPhaseProgram, PhaseEmissionError> {
    if program.semantic_hash() != plan.parent_semantic_hash
        || plan.cut_instruction == 0
        || plan.cut_instruction >= program.insts.len()
    {
        return Err(PhaseEmissionError::PlanProgramMismatch);
    }
    let canonical = WitnessPhasePlan::at_cut(program, plan.cut_instruction)
        .map_err(|_| PhaseEmissionError::PlanProgramMismatch)?;
    if canonical != *plan {
        return Err(PhaseEmissionError::PlanProgramMismatch);
    }
    let marked = compile_witness_to_marked_cuda_source(program)
        .ok_or(PhaseEmissionError::MarkedSourceUnavailable)?;
    let kernel_start = marked
        .find("extern \"C\" __global__")
        .ok_or(PhaseEmissionError::MalformedMarkedSource)?;
    let body_end = marked
        .strip_suffix("}\n")
        .map(str::len)
        .ok_or(PhaseEmissionError::MalformedMarkedSource)?;
    let support = &marked[..kernel_start];
    let mut markers = Vec::with_capacity(program.insts.len());
    let mut cursor = kernel_start;
    for instruction in 0..program.insts.len() {
        let needle = format!("    // STWO_WIT_INST_{instruction}\n");
        let relative = marked[cursor..]
            .find(&needle)
            .ok_or(PhaseEmissionError::MissingInstructionMarker(instruction))?;
        let position = cursor + relative;
        markers.push(position);
        cursor = position + needle.len();
    }
    if markers[plan.cut_instruction] >= body_end {
        return Err(PhaseEmissionError::MalformedMarkedSource);
    }
    let phase0_name = plan.phase_kernel_name(0);
    let phase1_name = plan.phase_kernel_name(1);
    let mut transports = BTreeMap::<TransportAnchor, Vec<(u32, String)>>::new();
    for store in &plan.moved_stores {
        transports
            .entry(store.transport_anchor)
            .or_default()
            .push((store.register, store_line(store.target, store.register)));
    }
    for value in &plan.boundary {
        if let BoundarySource::Scratch {
            slot,
            transport_anchor,
        } = value.source
        {
            transports.entry(transport_anchor).or_default().push((
                value.register,
                format!(
                    "    phase_scratch[{slot}u * row_count + row] = r{};\n",
                    value.register
                ),
            ));
        }
    }
    for stores in transports.values_mut() {
        stores.sort_by_key(|(register, _)| *register);
    }
    let expected_transports = transports.values().flatten().cloned().collect::<Vec<_>>();
    let mut phase0 = String::with_capacity(marked.len());
    phase0.push_str(support);
    emit_kernel_header(&mut phase0, &phase0_name);
    for instruction in 0..plan.cut_instruction {
        let mut body = segment(&marked, &markers, body_end, instruction).to_owned();
        let anchors = transports
            .keys()
            .copied()
            .filter(|anchor| anchor_instruction(*anchor) == instruction)
            .collect::<Vec<_>>();
        for anchor in anchors {
            let stores = transports.remove(&anchor).unwrap();
            if !insert_after_anchor(&mut body, anchor, &stores) {
                return Err(PhaseEmissionError::TransportStoreNotFound {
                    register: stores[0].0,
                });
            }
        }
        phase0.push_str(&body);
    }
    phase0.push_str("}\n");
    if let Some(stores) = transports.values().next() {
        return Err(PhaseEmissionError::TransportStoreNotFound {
            register: stores[0].0,
        });
    }
    for (register, line) in expected_transports {
        if phase0.matches(&line).count() != 1 {
            return Err(PhaseEmissionError::TransportStoreNotFound { register });
        }
    }
    let mut loads: BTreeMap<usize, Vec<_>> = BTreeMap::new();
    for value in &plan.boundary {
        loads
            .entry(value.first_suffix_instruction)
            .or_default()
            .push(*value);
    }
    for values in loads.values_mut() {
        values.sort_by_key(|value| value.register);
    }
    let suppressed = plan
        .moved_stores
        .iter()
        .map(|store| (*store, store_line(store.target, store.register)))
        .collect::<Vec<_>>();
    let mut suppression_counts = vec![0usize; suppressed.len()];

    let mut phase1 = String::with_capacity(marked.len());
    phase1.push_str(support);
    emit_kernel_header(&mut phase1, &phase1_name);
    for instruction in plan.cut_instruction..program.insts.len() {
        if let Some(values) = loads.get(&instruction) {
            for value in values {
                emit_lazy_load(&mut phase1, *value);
            }
        }
        let mut body = segment(&marked, &markers, body_end, instruction).to_owned();
        for (index, (_, line)) in suppressed.iter().enumerate() {
            let count = body.matches(line).count();
            suppression_counts[index] += count;
            if count != 0 {
                body = body.replace(line, "");
            }
        }
        phase1.push_str(&body);
    }
    phase1.push_str("}\n");
    for (index, (store, _)) in suppressed.iter().enumerate() {
        if suppression_counts[index] != 1 {
            return Err(PhaseEmissionError::MovedStoreNotFound {
                register: store.register,
                target: store.target,
            });
        }
    }

    Ok(EmittedWitnessPhaseProgram {
        parent_semantic_hash: plan.parent_semantic_hash,
        plan_hash: plan.plan_hash,
        scratch_words_per_row: plan.scratch_words_per_row,
        phases: vec![
            EmittedWitnessPhase {
                ordinal: 0,
                kernel_name: phase0_name,
                cache_key: plan.phase_cache_key(0),
                source: phase0,
            },
            EmittedWitnessPhase {
                ordinal: 1,
                kernel_name: phase1_name,
                cache_key: plan.phase_cache_key(1),
                source: phase1,
            },
        ],
    })
}

fn segment<'a>(source: &'a str, markers: &[usize], body_end: usize, index: usize) -> &'a str {
    let end = markers.get(index + 1).copied().unwrap_or(body_end);
    &source[markers[index]..end]
}

fn anchor_instruction(anchor: TransportAnchor) -> usize {
    match anchor {
        TransportAnchor::AfterInstruction(instruction)
        | TransportAnchor::AfterDeduceArguments(instruction) => instruction,
        TransportAnchor::AfterDeduceRegister { instruction, .. } => instruction,
    }
}

fn insert_after_anchor(
    source: &mut String,
    anchor: TransportAnchor,
    stores: &[(u32, String)],
) -> bool {
    let marker = match anchor {
        TransportAnchor::AfterInstruction(instruction) => {
            format!("    // STWO_WIT_AFTER_INST_{instruction}\n")
        }
        TransportAnchor::AfterDeduceArguments(instruction) => {
            format!("    // STWO_WIT_AFTER_DARGS_{instruction}\n")
        }
        TransportAnchor::AfterDeduceRegister {
            instruction,
            register,
            bank_offset,
        } => format!("    // STWO_WIT_AFTER_DREG_{instruction}_{register}_{bank_offset}\n"),
    };
    if source.matches(&marker).count() != 1 {
        return false;
    }
    let insertion = source.find(&marker).unwrap() + marker.len();
    let block = stores
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<String>();
    source.insert_str(insertion, &block);
    true
}

fn emit_kernel_header(source: &mut String, name: &str) {
    source.push_str(&format!(
        "extern \"C\" __global__ void __launch_bounds__(256) {name}(\n\
         \x20   const unsigned *const *input_cols,\n\
         \x20   const unsigned *const *table_bases,\n\
         \x20   const unsigned *table_strides,\n\
         \x20   unsigned *const *out_cols,\n\
         \x20   unsigned *const *mult_counts,\n\
         \x20   unsigned *lookup_words,\n\
         \x20   unsigned *sub_words,\n\
         \x20   unsigned *phase_scratch,\n\
         \x20   unsigned row_count\n\
         ) {{\n\
         \x20   unsigned row = blockIdx.x * blockDim.x + threadIdx.x;\n\
         \x20   if (row >= row_count) {{ return; }}\n\n"
    ));
}

fn emit_lazy_load(source: &mut String, value: super::phase_plan::BoundaryValue) {
    let expression = match value.source {
        BoundarySource::Constant(constant) => format!("{constant}u"),
        BoundarySource::Input(index) => format!("input_cols[{index}u][row]"),
        BoundarySource::Output(target) => target_expression(target),
        BoundarySource::Scratch { slot, .. } => {
            format!("phase_scratch[{slot}u * row_count + row]")
        }
    };
    source.push_str(&format!(
        "    unsigned r{} = {expression};\n",
        value.register
    ));
}

fn target_expression(target: PhaseOutputTarget) -> String {
    match target {
        PhaseOutputTarget::Column(index) => format!("out_cols[{index}u][row]"),
        PhaseOutputTarget::LookupWord(index) => {
            format!("lookup_words[{index}u * row_count + row]")
        }
        PhaseOutputTarget::SubWord(index) => {
            format!("sub_words[{index}u * row_count + row]")
        }
    }
}

fn store_line(target: PhaseOutputTarget, register: u32) -> String {
    match target {
        PhaseOutputTarget::Column(index) => {
            format!("    out_cols[{index}u][row] = r{register};\n")
        }
        PhaseOutputTarget::LookupWord(index) => {
            format!("    lookup_words[{index}u * row_count + row] = r{register};\n")
        }
        PhaseOutputTarget::SubWord(index) => {
            format!("    sub_words[{index}u * row_count + row] = r{register};\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::interp::{interpret_row_with, DeduceHost, RowOutputs};
    use super::super::super::isa::{DeduceKind, WitnessInst, WitnessOp};
    use super::super::super::recording::WitnessRecorder;
    use super::*;

    #[test]
    fn emitter_moves_unique_store_and_loads_only_at_first_suffix_use() {
        let mut recorder = WitnessRecorder::new("phase_emit");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let sum = recorder.m31_add(a, b);
        let stored_only = recorder.m31_sub(a, b);
        recorder.col_write(0, stored_only);
        let product = recorder.m31_mul(sum, b);
        recorder.col_write(1, product);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::at_cut(&program, 4).unwrap();
        let emitted = compile_witness_to_phase_sources(&program, &plan).unwrap();
        assert_eq!(emitted.phases.len(), 2);
        assert_eq!(emitted.scratch_words_per_row, 1);
        let moved = "out_cols[0u][row] = r3;";
        assert_eq!(emitted.phases[0].source.matches(moved).count(), 1);
        assert_eq!(emitted.phases[1].source.matches(moved).count(), 0);
        let load = emitted.phases[1]
            .source
            .find("unsigned r2 = phase_scratch[0u * row_count + row];")
            .unwrap();
        let use_position = emitted.phases[1]
            .source
            .find("stwo_m31_mul(r2, r1)")
            .unwrap();
        assert!(load < use_position);
        let mut forged = plan.clone();
        forged.plan_hash ^= 1;
        assert_eq!(
            compile_witness_to_phase_sources(&program, &forged),
            Err(PhaseEmissionError::PlanProgramMismatch)
        );
    }

    #[test]
    fn marked_subanchors_leave_monolithic_source_byte_identical() {
        let mut recorder = WitnessRecorder::new("phase_marker_regression");
        let inputs = (0..6)
            .map(|index| recorder.input(index))
            .collect::<Vec<_>>();
        let mixed = recorder.u32_xor(inputs[0], inputs[1]);
        recorder.mult_push(0, mixed);
        let deduced = recorder.deduce(DeduceKind::BlakeG, &inputs);
        recorder.col_write(0, mixed);
        recorder.col_write(1, deduced[0]);
        let program = recorder.finish();
        let production = super::super::compile_witness_to_cuda_source(&program).unwrap();
        let marked = compile_witness_to_marked_cuda_source(&program).unwrap();
        let stripped = marked
            .split_inclusive('\n')
            .filter(|line| !line.trim_start().starts_with("// STWO_WIT_"))
            .collect::<String>();
        assert_eq!(stripped.as_bytes(), production.as_bytes());
    }

    #[test]
    fn phase_interpreter_matches_whole_program_on_edges_and_fuzz() {
        let mut recorder = WitnessRecorder::new("phase_differential");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let constant = recorder.constant(17);
        let sum = recorder.m31_add(a, b);
        recorder.col_write(0, sum);
        let product = recorder.m31_mul(sum, constant);
        recorder.col_write(1, product);
        recorder.lookup_word(0, sum);
        recorder.sub_word(0, product);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::at_cut(&program, 4).unwrap();
        let mut rows = vec![vec![0, 0], vec![1, 2], vec![0x7fff_fffe, 1]];
        let mut state = 0x9e37_79b9u32;
        for _ in 0..64 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            rows.push(vec![
                state % 2_147_483_647,
                state.rotate_left(11) % 2_147_483_647,
            ]);
        }
        for inputs in rows {
            let mut full_host = NoDeduces;
            let expected = interpret_row_with(&program, &inputs, &|_, _, _| 0, &mut full_host);
            let actual = interpret_two_phase(&program, &plan, &inputs);
            assert_eq!(actual, expected, "inputs={inputs:?}");
        }
    }

    #[test]
    fn phase_oracle_covers_all_transport_anchors_and_source_positions() {
        let mut recorder = WitnessRecorder::new("phase_adversarial");
        let a = recorder.input(0);
        let b = recorder.input(1);
        let c = recorder.input(2);
        let d = recorder.input(3);
        let m0 = recorder.input(4);
        let m1 = recorder.input(5);
        let definition_only = recorder.u32_mul(a, b);
        let crossing = recorder.u32_xor(a, b);
        let deduce_argument = recorder.u32_add(m0, m1);
        recorder.mult_push(0, crossing);
        recorder.col_write(0, crossing);
        let deduced = recorder.deduce(DeduceKind::BlakeG, &[deduce_argument, b, c, d, m0, m1]);
        recorder.mult_push(0, crossing);
        recorder.mult_push(1, deduced[0]);
        let sum = recorder.u32_add(crossing, deduced[0]);
        let sum = recorder.u32_add(sum, definition_only);
        let sum = recorder.u32_add(sum, deduce_argument);
        recorder.col_write(0, sum);
        recorder.col_write(1, definition_only);
        recorder.col_write(2, deduce_argument);
        recorder.col_write(3, deduced[0]);
        let program = recorder.finish();
        let plan = WitnessPhasePlan::after_deduce(&program, 0).unwrap();
        let definition_instruction = program
            .insts
            .iter()
            .position(|inst| inst.dst == definition_only.0)
            .unwrap();
        let mult_instruction = program
            .insts
            .iter()
            .position(|inst| {
                WitnessOp::from_raw(inst.op) == Some(WitnessOp::MultPush)
                    && inst.a == u32::from(crossing.0)
            })
            .unwrap();
        let call_instruction = program
            .insts
            .iter()
            .position(|inst| WitnessOp::from_raw(inst.op) == Some(WitnessOp::DeduceCall))
            .unwrap();
        assert_eq!(plan.scratch_words_per_row, 1);
        let scratch_value = plan
            .boundary
            .iter()
            .find(|value| value.register == u32::from(crossing.0))
            .unwrap();
        let BoundarySource::Scratch {
            slot: 0,
            transport_anchor: scratch_anchor,
        } = scratch_value.source
        else {
            panic!("crossing value must use scratch")
        };
        assert_eq!(
            scratch_anchor,
            TransportAnchor::AfterInstruction(mult_instruction)
        );
        let moved = |register| {
            plan.moved_stores
                .iter()
                .find(|store| store.register == register)
                .unwrap()
        };
        assert_eq!(
            moved(u32::from(definition_only.0)).transport_anchor,
            TransportAnchor::AfterInstruction(definition_instruction)
        );
        assert_eq!(
            moved(u32::from(deduce_argument.0)).transport_anchor,
            TransportAnchor::AfterDeduceArguments(call_instruction)
        );
        assert_eq!(
            moved(u32::from(deduced[0].0)).transport_anchor,
            TransportAnchor::AfterDeduceRegister {
                instruction: call_instruction,
                register: deduced[0].0 as usize,
                bank_offset: 0,
            }
        );
        let emitted = compile_witness_to_phase_sources(&program, &plan).unwrap();
        let phase0 = &emitted.phases[0].source;
        let scratch_store = format!("phase_scratch[0u * row_count + row] = r{};", crossing.0);
        let scratch_load = format!(
            "unsigned r{} = phase_scratch[0u * row_count + row];",
            crossing.0
        );
        let definition_store = format!("out_cols[1u][row] = r{};", definition_only.0);
        let argument_store = format!("out_cols[2u][row] = r{};", deduce_argument.0);
        let deduced_store = format!("out_cols[3u][row] = r{};", deduced[0].0);
        let transport_stores = [
            &scratch_store,
            &definition_store,
            &argument_store,
            &deduced_store,
        ];
        for store in transport_stores {
            assert_eq!(phase0.matches(store).count(), 1, "{store}");
        }
        assert_eq!(emitted.phases[1].source.matches(&scratch_load).count(), 1);
        let position = |needle: &str| phase0.find(needle).unwrap_or_else(|| panic!("{needle}"));
        let definition_marker = format!("// STWO_WIT_AFTER_INST_{definition_instruction}");
        assert!(
            position(&format!("unsigned r{} =", definition_only.0)) < position(&definition_marker)
                && position(&definition_marker) < position(&definition_store)
        );
        let mult_marker = format!("// STWO_WIT_AFTER_INST_{mult_instruction}");
        assert!(
            position(&format!(
                "atomicAdd(&mult_counts[0u][r{}], 1u);",
                crossing.0
            )) < position(&mult_marker)
                && position(&mult_marker) < position(&scratch_store)
        );
        let argument_marker = format!("// STWO_WIT_AFTER_DARGS_{call_instruction}");
        assert!(
            position("const unsigned dargs0[6]") < position(&argument_marker)
                && position(&argument_marker) < position(&argument_store)
                && position(&argument_store) < position("stwo_wit_blake_g(dargs0, douts0);")
        );
        let deduced_marker = format!(
            "// STWO_WIT_AFTER_DREG_{call_instruction}_{}_0",
            deduced[0].0
        );
        assert!(
            position(&format!("unsigned r{} = douts0[0];", deduced[0].0))
                < position(&deduced_marker)
                && position(&deduced_marker) < position(&deduced_store)
                && position(&deduced_store)
                    < position(&format!("unsigned r{} = douts0[1];", deduced[1].0))
        );
        let final_marker = format!("// STWO_WIT_AFTER_INST_{call_instruction}");
        for store in transport_stores {
            assert!(
                position(store) < position(&final_marker),
                "tail store: {store}"
            );
        }
        let mut forged = plan.clone();
        forged
            .moved_stores
            .iter_mut()
            .find(|store| store.register == u32::from(deduce_argument.0))
            .unwrap()
            .transport_anchor = TransportAnchor::AfterInstruction(call_instruction);
        assert_eq!(
            compile_witness_to_phase_sources(&program, &forged),
            Err(PhaseEmissionError::PlanProgramMismatch)
        );
        let rows = [
            [0, 0, 0, 0, 0, 0],
            [1, 2, 3, 4, 5, 6],
            [u32::MAX, 0x8000_0000, 7, 11, 13, 17],
        ];
        for inputs in rows {
            let mut full_host = DeterministicBlakeG;
            let expected = interpret_row_with(&program, &inputs, &|_, _, _| 0, &mut full_host);
            let mut phase_host = DeterministicBlakeG;
            let actual = interpret_two_phase_with(&program, &plan, &inputs, &mut phase_host);
            assert_eq!(actual, expected, "inputs={inputs:?}");
            assert_eq!(actual.mults.len(), 3);
            assert_eq!(
                actual
                    .mults
                    .iter()
                    .map(|(table, _)| *table)
                    .collect::<Vec<_>>(),
                [0, 0, 1]
            );
        }
    }

    struct NoDeduces;
    impl DeduceHost for NoDeduces {
        fn deduce(&mut self, kind: u32, _args: &[u32]) -> Vec<u32> {
            panic!("unexpected deduce {kind}")
        }
    }

    struct DeterministicBlakeG;
    impl DeduceHost for DeterministicBlakeG {
        fn deduce(&mut self, kind: u32, args: &[u32]) -> Vec<u32> {
            assert_eq!(kind, DeduceKind::BlakeG as u32);
            assert_eq!(args.len(), 6);
            vec![
                args[0].wrapping_add(args[4]),
                args[1] ^ args[5],
                args[2].rotate_left(7),
                args[3].wrapping_sub(args[0]),
            ]
        }
    }

    fn interpret_two_phase(
        program: &WitnessProgram,
        plan: &WitnessPhasePlan,
        inputs: &[u32],
    ) -> RowOutputs {
        interpret_two_phase_with(program, plan, inputs, &mut NoDeduces)
    }

    fn interpret_two_phase_with(
        program: &WitnessProgram,
        plan: &WitnessPhasePlan,
        inputs: &[u32],
        host: &mut dyn DeduceHost,
    ) -> RowOutputs {
        let is_moved = |inst: &WitnessInst| {
            plan.moved_stores
                .iter()
                .any(|store| inst.a == store.register && output_target(inst) == Some(store.target))
        };
        let mut prefix = program.insts[..plan.cut_instruction]
            .iter()
            .copied()
            .filter(|inst| !is_moved(inst))
            .collect::<Vec<_>>();
        for store in &plan.moved_stores {
            prefix.push(output_inst(store.target, store.register));
        }
        for value in &plan.boundary {
            if let BoundarySource::Scratch { slot, .. } = value.source {
                prefix.push(WitnessInst::new(
                    WitnessOp::ColWrite,
                    0,
                    value.register,
                    0,
                    program.n_cols + slot,
                ));
            }
        }
        let prefix_program = WitnessProgram {
            label: "phase0".to_string(),
            insts: prefix,
            n_regs: program.n_regs,
            n_inputs: program.n_inputs,
            n_cols: program.n_cols + plan.scratch_words_per_row,
            n_mult_tables: program.n_mult_tables,
            n_lookup_words: program.n_lookup_words,
            n_sub_words: program.n_sub_words,
        };
        let phase0 = interpret_row_with(&prefix_program, inputs, &|_, _, _| 0, host);
        let mut suffix = Vec::new();
        let mut phase1_inputs = inputs.to_vec();
        for value in &plan.boundary {
            let definition = match value.source {
                BoundarySource::Constant(constant) => {
                    WitnessInst::new(WitnessOp::Const, value.register as u16, 0, 0, constant)
                }
                BoundarySource::Input(index) => {
                    WitnessInst::new(WitnessOp::Input, value.register as u16, index, 0, 0)
                }
                BoundarySource::Output(target) => {
                    let transported = read_target(&phase0, target);
                    let index = phase1_inputs.len() as u32;
                    phase1_inputs.push(transported);
                    WitnessInst::new(WitnessOp::Input, value.register as u16, index, 0, 0)
                }
                BoundarySource::Scratch { slot, .. } => {
                    let transported = phase0.columns[(program.n_cols + slot) as usize];
                    let index = phase1_inputs.len() as u32;
                    phase1_inputs.push(transported);
                    WitnessInst::new(WitnessOp::Input, value.register as u16, index, 0, 0)
                }
            };
            suffix.push(definition);
        }
        suffix.extend(
            program.insts[plan.cut_instruction..]
                .iter()
                .copied()
                .filter(|inst| !is_moved(inst)),
        );
        let suffix_program = WitnessProgram {
            label: "phase1".to_string(),
            insts: suffix,
            n_regs: program.n_regs,
            n_inputs: phase1_inputs.len() as u32,
            n_cols: program.n_cols,
            n_mult_tables: program.n_mult_tables,
            n_lookup_words: program.n_lookup_words,
            n_sub_words: program.n_sub_words,
        };
        let phase1 = interpret_row_with(&suffix_program, &phase1_inputs, &|_, _, _| 0, host);
        let mut result = RowOutputs {
            columns: phase0.columns[..program.n_cols as usize].to_vec(),
            mults: phase0.mults,
            lookup_words: phase0.lookup_words,
            sub_words: phase0.sub_words,
        };
        result.mults.extend(phase1.mults);
        for inst in &suffix_program.insts {
            match WitnessOp::from_raw(inst.op) {
                Some(WitnessOp::ColWrite) => {
                    result.columns[inst.imm as usize] = phase1.columns[inst.imm as usize]
                }
                Some(WitnessOp::LookupWord) => {
                    result.lookup_words[inst.imm as usize] = phase1.lookup_words[inst.imm as usize]
                }
                Some(WitnessOp::SubWord) => {
                    result.sub_words[inst.imm as usize] = phase1.sub_words[inst.imm as usize]
                }
                _ => {}
            }
        }
        result
    }

    fn output_target(inst: &WitnessInst) -> Option<PhaseOutputTarget> {
        Some(match WitnessOp::from_raw(inst.op)? {
            WitnessOp::ColWrite => PhaseOutputTarget::Column(inst.imm),
            WitnessOp::LookupWord => PhaseOutputTarget::LookupWord(inst.imm),
            WitnessOp::SubWord => PhaseOutputTarget::SubWord(inst.imm),
            _ => return None,
        })
    }

    fn output_inst(target: PhaseOutputTarget, register: u32) -> WitnessInst {
        let (op, ordinal) = match target {
            PhaseOutputTarget::Column(index) => (WitnessOp::ColWrite, index),
            PhaseOutputTarget::LookupWord(index) => (WitnessOp::LookupWord, index),
            PhaseOutputTarget::SubWord(index) => (WitnessOp::SubWord, index),
        };
        WitnessInst::new(op, 0, register, 0, ordinal)
    }

    fn read_target(outputs: &RowOutputs, target: PhaseOutputTarget) -> u32 {
        match target {
            PhaseOutputTarget::Column(index) => outputs.columns[index as usize],
            PhaseOutputTarget::LookupWord(index) => outputs.lookup_words[index as usize],
            PhaseOutputTarget::SubWord(index) => outputs.sub_words[index as usize],
        }
    }
}
