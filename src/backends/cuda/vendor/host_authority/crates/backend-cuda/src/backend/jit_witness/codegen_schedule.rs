//! Correctness boundary for witness-JIT output-store scheduling.
//!
//! Witness bytecode is SSA. CUDA output stores may move to the source value's final
//! computational use because output/multiplicity buffers are disjoint and computed
//! deduces are pure reads. Duplicate target writes retain source order. Keeping this
//! logic separate makes the resource optimization executable by the host interpreter.
//! Bytecode register redefinition fails closed: compact physical reuse is ptxas's job
//! after these shortened C-level live ranges, not a second, implicit bytecode model.

use std::collections::HashMap;

use super::super::isa::{DeduceKind, WitnessOp, WitnessProgram};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ScheduledOutput {
    pub(super) op: WitnessOp,
    pub(super) register: u32,
    pub(super) ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum StoreAnchor {
    AfterInstruction(usize),
    AfterDeduceArguments(usize),
    AfterDeduceRegister {
        instruction: usize,
        register: usize,
        bank_offset: usize,
    },
}

impl StoreAnchor {
    pub(super) fn rank(self) -> (usize, usize) {
        match self {
            Self::AfterInstruction(instruction) => (instruction, usize::MAX),
            Self::AfterDeduceArguments(instruction) => (instruction, 0),
            Self::AfterDeduceRegister {
                instruction,
                bank_offset,
                ..
            } => (instruction, bank_offset + 1),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct RegisterDefinition {
    pub(super) instruction: usize,
    pub(super) deduce_bank_offset: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub(super) enum OutputTarget {
    Column(u32),
    LookupWord(u32),
    SubWord(u32),
}

impl ScheduledOutput {
    pub(super) fn target(self) -> OutputTarget {
        match self.op {
            WitnessOp::ColWrite => OutputTarget::Column(self.ordinal),
            WitnessOp::LookupWord => OutputTarget::LookupWord(self.ordinal),
            WitnessOp::SubWord => OutputTarget::SubWord(self.ordinal),
            _ => unreachable!("scheduled output is always a value store"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct StoreEvent {
    pub(super) anchor: StoreAnchor,
    pub(super) order: usize,
    pub(super) output: ScheduledOutput,
}

/// One validated SSA/output analysis shared by monolithic scheduling and the
/// experimental phase planner. Computational uses and scheduled stores remain
/// explicit, so the planner can account for both at every phase boundary.
pub(super) struct ProgramAnalysis {
    pub(super) schedule: OutputSchedule,
    pub(super) definitions: Vec<Option<RegisterDefinition>>,
    pub(super) computational_uses: Vec<Vec<usize>>,
    pub(super) deduce_argument_uses: Vec<Vec<usize>>,
    pub(super) legal_cuts: Vec<bool>,
    pub(super) stores: Vec<StoreEvent>,
}

pub(super) struct OutputSchedule {
    pub(super) after_instruction: Vec<Vec<ScheduledOutput>>,
    pub(super) after_deduce_arguments: Vec<Vec<ScheduledOutput>>,
    pub(super) after_deduce_register: Vec<Vec<ScheduledOutput>>,
}

impl OutputSchedule {
    /// Build the earliest legal store schedule, rejecting malformed or non-SSA input.
    pub(super) fn build(program: &WitnessProgram) -> Option<Self> {
        Some(Self::analyze(program)?.schedule)
    }

    pub(super) fn analyze(program: &WitnessProgram) -> Option<ProgramAnalysis> {
        let n_regs = program.n_regs as usize;
        let mut definitions = vec![None; n_regs];
        let mut last_use = vec![None; n_regs];
        let mut deduce_argument_uses = vec![Vec::new(); n_regs];
        let mut pending_deduce_args = Vec::new();
        let mut outputs = Vec::new();

        for (instruction, inst) in program.insts.iter().enumerate() {
            let op = WitnessOp::from_raw(inst.op)?;
            match op {
                WitnessOp::Input => {
                    (inst.a < program.n_inputs).then_some(())?;
                    define_register(
                        inst.dst as usize,
                        instruction,
                        None,
                        &mut definitions,
                        &mut last_use,
                    )?;
                }
                WitnessOp::Const => define_register(
                    inst.dst as usize,
                    instruction,
                    None,
                    &mut definitions,
                    &mut last_use,
                )?,
                WitnessOp::M31Add
                | WitnessOp::M31Sub
                | WitnessOp::M31Mul
                | WitnessOp::U16Add
                | WitnessOp::U32Add
                | WitnessOp::U32Sub
                | WitnessOp::U32Mul
                | WitnessOp::U32Xor
                | WitnessOp::M31Eq => {
                    mark_use(inst.a, instruction, &definitions, &mut last_use)?;
                    mark_use(inst.b, instruction, &definitions, &mut last_use)?;
                    define_register(
                        inst.dst as usize,
                        instruction,
                        None,
                        &mut definitions,
                        &mut last_use,
                    )?;
                }
                WitnessOp::M31Neg
                | WitnessOp::U16Shl
                | WitnessOp::U16Shr
                | WitnessOp::U16And
                | WitnessOp::U32Shl
                | WitnessOp::U32Shr
                | WitnessOp::U32And
                | WitnessOp::AsM31
                | WitnessOp::Trunc16
                | WitnessOp::TableLimb
                | WitnessOp::M31Inverse => {
                    mark_use(inst.a, instruction, &definitions, &mut last_use)?;
                    define_register(
                        inst.dst as usize,
                        instruction,
                        None,
                        &mut definitions,
                        &mut last_use,
                    )?;
                }
                WitnessOp::MultPush => {
                    mark_use(inst.a, instruction, &definitions, &mut last_use)?;
                }
                WitnessOp::DeduceArg => {
                    definition(inst.a, &definitions)?;
                    pending_deduce_args.push(inst.a);
                }
                WitnessOp::DeduceCall => {
                    let kind = DeduceKind::from_raw(inst.imm)?;
                    let (n_args, n_outs) = kind.shape();
                    (pending_deduce_args.len() == n_args && inst.b as usize == n_outs)
                        .then_some(())?;
                    for register in pending_deduce_args.drain(..) {
                        mark_use(register, instruction, &definitions, &mut last_use)?;
                        deduce_argument_uses[register as usize].push(instruction);
                    }
                    let end = (inst.dst as usize).checked_add(n_outs)?;
                    (end <= n_regs).then_some(())?;
                    for (bank_offset, register) in (inst.dst as usize..end).enumerate() {
                        define_register(
                            register,
                            instruction,
                            Some(bank_offset),
                            &mut definitions,
                            &mut last_use,
                        )?;
                    }
                }
                WitnessOp::ColWrite | WitnessOp::LookupWord | WitnessOp::SubWord => {
                    definition(inst.a, &definitions)?;
                    let bound = match op {
                        WitnessOp::ColWrite => program.n_cols,
                        WitnessOp::LookupWord => program.n_lookup_words,
                        WitnessOp::SubWord => program.n_sub_words,
                        _ => unreachable!(),
                    };
                    (inst.imm < bound).then_some(())?;
                    outputs.push(ScheduledOutput {
                        op,
                        register: inst.a,
                        ordinal: inst.imm,
                    });
                }
            }
        }
        pending_deduce_args.is_empty().then_some(())?;

        let computational_uses = collect_instruction_uses(program, n_regs)?;
        for register in 0..n_regs {
            let definition = definitions[register]?;
            let expected_last = computational_uses[register]
                .last()
                .copied()
                .unwrap_or(definition.instruction);
            (last_use[register] == Some(expected_last)).then_some(())?;
        }

        let mut schedule = Self {
            after_instruction: vec![Vec::new(); program.insts.len()],
            after_deduce_arguments: vec![Vec::new(); program.insts.len()],
            after_deduce_register: vec![Vec::new(); n_regs],
        };
        let mut previous_target_anchor: HashMap<(u8, u32), StoreAnchor> = HashMap::new();
        for output in outputs {
            let register = output.register as usize;
            let definition = definitions[register]?;
            let last_use = last_use[register]?;
            let mut anchor = if deduce_argument_uses[register].last() == Some(&last_use) {
                StoreAnchor::AfterDeduceArguments(last_use)
            } else {
                match definition.deduce_bank_offset {
                    Some(bank_offset) if last_use == definition.instruction => {
                        StoreAnchor::AfterDeduceRegister {
                            instruction: definition.instruction,
                            register,
                            bank_offset,
                        }
                    }
                    _ => StoreAnchor::AfterInstruction(last_use),
                }
            };
            let target = (output.op as u8, output.ordinal);
            if let Some(previous) = previous_target_anchor.get(&target).copied() {
                if previous.rank() > anchor.rank() {
                    anchor = previous;
                }
            }
            previous_target_anchor.insert(target, anchor);
            match anchor {
                StoreAnchor::AfterInstruction(instruction) => {
                    schedule.after_instruction[instruction].push(output)
                }
                StoreAnchor::AfterDeduceArguments(instruction) => {
                    schedule.after_deduce_arguments[instruction].push(output)
                }
                StoreAnchor::AfterDeduceRegister { register, .. } => {
                    schedule.after_deduce_register[register].push(output)
                }
            }
        }
        let mut stores = Vec::new();
        for instruction in 0..program.insts.len() {
            for (order, output) in schedule.after_deduce_arguments[instruction]
                .iter()
                .copied()
                .enumerate()
            {
                stores.push(StoreEvent {
                    anchor: StoreAnchor::AfterDeduceArguments(instruction),
                    order,
                    output,
                });
            }
            for (order, output) in schedule.after_instruction[instruction]
                .iter()
                .copied()
                .enumerate()
            {
                stores.push(StoreEvent {
                    anchor: StoreAnchor::AfterInstruction(instruction),
                    order,
                    output,
                });
            }
        }
        for (register, outputs) in schedule.after_deduce_register.iter().enumerate() {
            if outputs.is_empty() {
                continue;
            }
            let definition = definitions[register]?;
            let bank_offset = definition.deduce_bank_offset?;
            for (order, output) in outputs.iter().copied().enumerate() {
                stores.push(StoreEvent {
                    anchor: StoreAnchor::AfterDeduceRegister {
                        instruction: definition.instruction,
                        register,
                        bank_offset,
                    },
                    order,
                    output,
                });
            }
        }
        stores.sort_by_key(|event| (event.anchor.rank(), event.order));
        let legal_cuts = legal_cuts(program)?;
        Some(ProgramAnalysis {
            schedule,
            definitions,
            computational_uses,
            deduce_argument_uses,
            legal_cuts,
            stores,
        })
    }
}

fn collect_instruction_uses(program: &WitnessProgram, n_regs: usize) -> Option<Vec<Vec<usize>>> {
    let mut uses = vec![Vec::new(); n_regs];
    let mut pending_deduce_args = Vec::new();
    let mut push = |register: u32, instruction: usize| -> Option<()> {
        uses.get_mut(register as usize)?.push(instruction);
        Some(())
    };
    for (instruction, inst) in program.insts.iter().enumerate() {
        match WitnessOp::from_raw(inst.op)? {
            WitnessOp::Input | WitnessOp::Const => {}
            WitnessOp::M31Add
            | WitnessOp::M31Sub
            | WitnessOp::M31Mul
            | WitnessOp::U16Add
            | WitnessOp::U32Add
            | WitnessOp::U32Sub
            | WitnessOp::U32Mul
            | WitnessOp::U32Xor
            | WitnessOp::M31Eq => {
                push(inst.a, instruction)?;
                push(inst.b, instruction)?;
            }
            WitnessOp::M31Neg
            | WitnessOp::U16Shl
            | WitnessOp::U16Shr
            | WitnessOp::U16And
            | WitnessOp::U32Shl
            | WitnessOp::U32Shr
            | WitnessOp::U32And
            | WitnessOp::AsM31
            | WitnessOp::Trunc16
            | WitnessOp::TableLimb
            | WitnessOp::M31Inverse
            | WitnessOp::MultPush => push(inst.a, instruction)?,
            WitnessOp::DeduceArg => pending_deduce_args.push(inst.a),
            WitnessOp::DeduceCall => {
                for register in pending_deduce_args.drain(..) {
                    push(register, instruction)?;
                }
            }
            WitnessOp::ColWrite | WitnessOp::LookupWord | WitnessOp::SubWord => {
                // Actual output uses are added from the validated schedule below.
            }
        }
    }
    pending_deduce_args.is_empty().then_some(uses)
}

fn legal_cuts(program: &WitnessProgram) -> Option<Vec<bool>> {
    let mut cuts = vec![false; program.insts.len() + 1];
    cuts[0] = true;
    let mut pending = 0usize;
    for (instruction, inst) in program.insts.iter().enumerate() {
        match WitnessOp::from_raw(inst.op)? {
            WitnessOp::DeduceArg => pending += 1,
            WitnessOp::DeduceCall => pending = 0,
            _ => {}
        }
        cuts[instruction + 1] = pending == 0;
    }
    Some(cuts)
}

pub(super) fn emit_scheduled_outputs(src: &mut String, outputs: &[ScheduledOutput]) -> Option<()> {
    for output in outputs {
        match output.op {
            WitnessOp::ColWrite => src.push_str(&format!(
                "    out_cols[{}u][row] = r{};\n",
                output.ordinal, output.register
            )),
            WitnessOp::LookupWord => src.push_str(&format!(
                "    lookup_words[{}u * row_count + row] = r{};\n",
                output.ordinal, output.register
            )),
            WitnessOp::SubWord => src.push_str(&format!(
                "    sub_words[{}u * row_count + row] = r{};\n",
                output.ordinal, output.register
            )),
            _ => return None,
        }
    }
    Some(())
}

fn definition(
    register: u32,
    definitions: &[Option<RegisterDefinition>],
) -> Option<RegisterDefinition> {
    definitions.get(register as usize).copied().flatten()
}

fn mark_use(
    register: u32,
    instruction: usize,
    definitions: &[Option<RegisterDefinition>],
    last_use: &mut [Option<usize>],
) -> Option<()> {
    definition(register, definitions)?;
    *last_use.get_mut(register as usize)? = Some(instruction);
    Some(())
}

fn define_register(
    register: usize,
    instruction: usize,
    deduce_bank_offset: Option<usize>,
    definitions: &mut [Option<RegisterDefinition>],
    last_use: &mut [Option<usize>],
) -> Option<()> {
    let definition = definitions.get_mut(register)?;
    definition.is_none().then_some(())?;
    *definition = Some(RegisterDefinition {
        instruction,
        deduce_bank_offset,
    });
    *last_use.get_mut(register)? = Some(instruction);
    Some(())
}

/// Render the production schedule back to bytecode for a functional differential.
/// Bytecode has no per-bank-assignment opcode, so bank stores follow the call in the
/// same extraction order used by CUDA source generation.
#[cfg(test)]
fn scheduled_program(program: &WitnessProgram) -> Option<WitnessProgram> {
    use super::super::isa::WitnessInst;

    fn append(insts: &mut Vec<WitnessInst>, outputs: &[ScheduledOutput]) {
        insts.extend(
            outputs
                .iter()
                .map(|output| WitnessInst::new(output.op, 0, output.register, 0, output.ordinal)),
        );
    }

    let schedule = OutputSchedule::build(program)?;
    let mut insts = Vec::with_capacity(program.insts.len());
    for (instruction, inst) in program.insts.iter().enumerate() {
        let op = WitnessOp::from_raw(inst.op)?;
        if matches!(
            op,
            WitnessOp::ColWrite | WitnessOp::LookupWord | WitnessOp::SubWord
        ) {
            continue;
        }
        if op == WitnessOp::DeduceCall {
            append(&mut insts, &schedule.after_deduce_arguments[instruction]);
        }
        insts.push(*inst);
        if op == WitnessOp::DeduceCall {
            let (_, n_outs) = DeduceKind::from_raw(inst.imm)?.shape();
            let end = (inst.dst as usize).checked_add(n_outs)?;
            for register in inst.dst as usize..end {
                append(&mut insts, &schedule.after_deduce_register[register]);
            }
        }
        append(&mut insts, &schedule.after_instruction[instruction]);
    }
    let mut scheduled = program.clone();
    scheduled.insts = insts;
    Some(scheduled)
}

#[cfg(test)]
mod tests {
    use super::super::super::interp::{interpret_row_with, DeduceHost};
    use super::super::super::isa::WitnessOp;
    use super::super::super::recording::WitnessRecorder;
    use super::*;

    struct BlakeHost;

    impl DeduceHost for BlakeHost {
        fn deduce(&mut self, kind: u32, args: &[u32]) -> Vec<u32> {
            assert_eq!(kind, DeduceKind::BlakeG as u32);
            let (mut a, mut b, mut c, mut d, m0, m1) =
                (args[0], args[1], args[2], args[3], args[4], args[5]);
            a = a.wrapping_add(b).wrapping_add(m0);
            d = (d ^ a).rotate_right(16);
            c = c.wrapping_add(d);
            b = (b ^ c).rotate_right(12);
            a = a.wrapping_add(b).wrapping_add(m1);
            d = (d ^ a).rotate_right(8);
            c = c.wrapping_add(d);
            b = (b ^ c).rotate_right(7);
            vec![a, b, c, d]
        }
    }

    fn adversarial_program() -> WitnessProgram {
        let mut recorder = WitnessRecorder::new("scheduled_oracle");
        let inputs = (0..6)
            .map(|index| recorder.input(index))
            .collect::<Vec<_>>();
        let sum = recorder.u32_add(inputs[0], inputs[1]);
        recorder.mult_push(0, sum);
        let outputs = recorder.deduce(DeduceKind::BlakeG, &inputs);
        let mixed = recorder.u32_xor(outputs[0], outputs[1]);
        recorder.mult_push(1, mixed);
        recorder.col_write(0, inputs[0]);
        recorder.col_write(1, outputs[3]);
        recorder.lookup_word(0, outputs[0]);
        recorder.sub_word(0, inputs[2]);
        recorder.col_write(2, mixed);
        recorder.col_write(0, outputs[1]);
        recorder.finish()
    }

    #[test]
    fn scheduled_order_is_functionally_identical() {
        let conventional = adversarial_program();
        let scheduled = scheduled_program(&conventional).expect("valid schedule");
        assert_ne!(conventional.insts, scheduled.insts);

        let mut state = 0x6a09_e667u32;
        for row in 0..257 {
            let inputs = std::array::from_fn::<_, 6, _>(|lane| {
                state = state
                    .wrapping_mul(1_664_525)
                    .wrapping_add(1_013_904_223 ^ lane as u32 ^ row);
                state
            });
            let expected = interpret_row_with(&conventional, &inputs, &|_, _, _| 0, &mut BlakeHost);
            let actual = interpret_row_with(&scheduled, &inputs, &|_, _, _| 0, &mut BlakeHost);
            assert_eq!(actual, expected, "row {row}");
        }
    }

    #[test]
    fn non_ssa_reuse_and_malformed_deduce_banks_fail_closed() {
        let program = adversarial_program();

        let mut reused = program.clone();
        let second_definition = reused
            .insts
            .iter_mut()
            .find(|inst| WitnessOp::from_raw(inst.op) == Some(WitnessOp::U32Add))
            .unwrap();
        second_definition.dst = 0;
        assert!(OutputSchedule::build(&reused).is_none());

        let mut wrong_bank = program;
        let call = wrong_bank
            .insts
            .iter_mut()
            .find(|inst| WitnessOp::from_raw(inst.op) == Some(WitnessOp::DeduceCall))
            .unwrap();
        call.b -= 1;
        assert!(OutputSchedule::build(&wrong_bank).is_none());
    }
}
