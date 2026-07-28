//! Differential check between an official `FrameworkEval` and its recorded V1 program.
//!
//! This runs at bundle-generation time. It prevents a recorder implementation bug
//! from becoming an authenticated but semantically incorrect AIR artifact.

use anyhow::{Result, anyhow, ensure};
use num_traits::{One, Zero};
use stwo::core::air::accumulation::PointEvaluationAccumulator;
use stwo::core::fields::FieldExpOps;
use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::TreeVec;
use stwo_constraint_framework::{FrameworkEval, InfoEvaluator, PointEvaluator};

use crate::program::{
    MetalEvaluationProgramBaseOpcodeV1, MetalEvaluationProgramExtOpcodeV1,
    OwnedMetalEvaluationProgramV1,
};

const RANDOM_COEFFICIENT: SecureField = SecureField::from_u32_unchecked(101, 103, 107, 109);

pub fn validate<F: FrameworkEval>(
    component: &str,
    eval: &F,
    claimed_sum: SecureField,
    program: &OwnedMetalEvaluationProgramV1,
) -> Result<()> {
    let info = eval.evaluate(InfoEvaluator::new(eval.log_size(), Vec::new(), claimed_sum));
    let masks = deterministic_masks(&info);
    let borrowed = TreeVec(
        masks
            .iter()
            .map(|columns| columns.iter().collect::<Vec<_>>())
            .collect(),
    );

    let mut direct_accumulator = PointEvaluationAccumulator::new(RANDOM_COEFFICIENT);
    drop(eval.evaluate(PointEvaluator::new(
        borrowed,
        &mut direct_accumulator,
        SecureField::one(),
        eval.log_size(),
        claimed_sum,
    )));
    let direct = direct_accumulator.finalize();
    let recorded = evaluate_program(program, &masks)?;
    ensure!(
        direct == recorded,
        "{component}: recorded AIR semantic differential failed: direct={direct:?} recorded={recorded:?}"
    );
    Ok(())
}

fn deterministic_masks(info: &InfoEvaluator) -> Vec<Vec<Vec<SecureField>>> {
    let interaction_count = info.mask_offsets.len().max(3);
    let mut masks = vec![Vec::new(); interaction_count];
    masks[0] = (0..info.preprocessed_columns.len())
        .map(|column| vec![mask_value(0, column, 0)])
        .collect();
    for (interaction, columns) in info.mask_offsets.iter().enumerate() {
        if interaction == 0 {
            continue;
        }
        masks[interaction] = columns
            .iter()
            .enumerate()
            .map(|(column, offsets)| {
                offsets
                    .iter()
                    .enumerate()
                    .map(|(sample, _)| mask_value(interaction, column, sample))
                    .collect()
            })
            .collect();
    }
    masks
}

fn mask_value(interaction: usize, column: usize, sample: usize) -> SecureField {
    let seed = 17u32
        .wrapping_add((interaction as u32).wrapping_mul(10_007))
        .wrapping_add((column as u32).wrapping_mul(131))
        .wrapping_add((sample as u32).wrapping_mul(19));
    SecureField::from_u32_unchecked(seed, seed + 1, seed + 3, seed + 7)
}

fn evaluate_program(
    program: &OwnedMetalEvaluationProgramV1,
    masks: &[Vec<Vec<SecureField>>],
) -> Result<SecureField> {
    let header = program.header();
    ensure!(
        header.n_base_params == 0 && header.n_ext_params == 0,
        "semantic differential requires a concrete AIR program"
    );
    let mut base = vec![SecureField::zero(); header.max_base_regs as usize];
    let mut extension = vec![SecureField::zero(); header.max_ext_regs as usize];

    for instruction in program.base_insts() {
        let operation = MetalEvaluationProgramBaseOpcodeV1::from_raw(instruction.op)
            .ok_or_else(|| anyhow!("invalid base opcode {}", instruction.op))?;
        base[instruction.dst as usize] = match operation {
            MetalEvaluationProgramBaseOpcodeV1::TraceCol
            | MetalEvaluationProgramBaseOpcodeV1::PreprocessedCol => trace_value(
                masks,
                instruction.interaction as usize,
                instruction.a as usize,
                instruction.imm,
                program,
            )?,
            MetalEvaluationProgramBaseOpcodeV1::Param => {
                return Err(anyhow!("unexpected concrete base parameter"));
            }
            MetalEvaluationProgramBaseOpcodeV1::Const => {
                SecureField::from(BaseField::from_u32_unchecked(instruction.a))
            }
            MetalEvaluationProgramBaseOpcodeV1::Add => {
                base[instruction.a as usize] + base[instruction.b as usize]
            }
            MetalEvaluationProgramBaseOpcodeV1::Sub => {
                base[instruction.a as usize] - base[instruction.b as usize]
            }
            MetalEvaluationProgramBaseOpcodeV1::Mul => {
                base[instruction.a as usize] * base[instruction.b as usize]
            }
            MetalEvaluationProgramBaseOpcodeV1::Neg => -base[instruction.a as usize],
            MetalEvaluationProgramBaseOpcodeV1::Inv => base[instruction.a as usize].inverse(),
        };
    }

    for instruction in program.ext_insts() {
        let operation = MetalEvaluationProgramExtOpcodeV1::from_raw(instruction.op)
            .ok_or_else(|| anyhow!("invalid extension opcode {}", instruction.op))?;
        extension[instruction.dst as usize] = match operation {
            MetalEvaluationProgramExtOpcodeV1::SecureCol => SecureField::from_partial_evals([
                base[instruction.a as usize],
                base[instruction.b as usize],
                base[instruction.c as usize],
                base[instruction.d as usize],
            ]),
            MetalEvaluationProgramExtOpcodeV1::Param => {
                return Err(anyhow!("unexpected concrete extension parameter"));
            }
            MetalEvaluationProgramExtOpcodeV1::Const => SecureField::from_u32_unchecked(
                instruction.a,
                instruction.b,
                instruction.c,
                instruction.d,
            ),
            MetalEvaluationProgramExtOpcodeV1::Add => {
                extension[instruction.a as usize] + extension[instruction.b as usize]
            }
            MetalEvaluationProgramExtOpcodeV1::Sub => {
                extension[instruction.a as usize] - extension[instruction.b as usize]
            }
            MetalEvaluationProgramExtOpcodeV1::Mul => {
                extension[instruction.a as usize] * extension[instruction.b as usize]
            }
            MetalEvaluationProgramExtOpcodeV1::Neg => -extension[instruction.a as usize],
        };
    }

    let mut accumulator = PointEvaluationAccumulator::new(RANDOM_COEFFICIENT);
    for root in program.constraint_roots() {
        accumulator.accumulate(extension[*root as usize]);
    }
    Ok(accumulator.finalize())
}

fn trace_value(
    masks: &[Vec<Vec<SecureField>>],
    interaction: usize,
    column: usize,
    offset: i32,
    program: &OwnedMetalEvaluationProgramV1,
) -> Result<SecureField> {
    let samples = masks
        .get(interaction)
        .and_then(|columns| columns.get(column))
        .ok_or_else(|| anyhow!("AIR mask index is out of range"))?;
    if interaction == 0 {
        ensure!(
            offset == 0 && samples.len() == 1,
            "invalid preprocessed mask"
        );
        return Ok(samples[0]);
    }

    let mut observed = Vec::new();
    for instruction in program.base_insts() {
        if instruction.interaction as usize == interaction
            && instruction.a as usize == column
            && matches!(
                MetalEvaluationProgramBaseOpcodeV1::from_raw(instruction.op),
                Some(
                    MetalEvaluationProgramBaseOpcodeV1::TraceCol
                        | MetalEvaluationProgramBaseOpcodeV1::PreprocessedCol
                )
            )
            && !observed.contains(&instruction.imm)
        {
            observed.push(instruction.imm);
        }
    }
    let sample = observed
        .iter()
        .position(|candidate| *candidate == offset)
        .ok_or_else(|| anyhow!("AIR mask offset is missing"))?;
    samples
        .get(sample)
        .copied()
        .ok_or_else(|| anyhow!("AIR mask sample is out of range"))
}
