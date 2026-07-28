use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use stwo::core::air::Component as ComponentTrait;
use stwo::core::constraints::coset_vanishing;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::utils::bit_reverse;
use stwo_constraint_framework::{FrameworkComponent, FrameworkEval};

use crate::encoding::{program as encode_program, push_u16, push_u32, push_u64};
use crate::parameters::ExtSource;
use crate::program::OwnedMetalEvaluationProgramV1;

const MAGIC: &[u8; 8] = b"STWZEVA\0";
const VERSION: u32 = 1;
const MAX_KERNEL_INSTRUCTIONS: u32 = 1_000_000;
const PLAN_HASH_OFFSET: usize = 32;

pub struct CapturedComponent {
    label: String,
    instance: u32,
    trace_log_size: u32,
    evaluation_log_size: u32,
    n_constraints: u32,
    random_coefficient_offset: u32,
    trace_spans: Vec<(u32, u32, u32)>,
    preprocessed_indices: Vec<u32>,
    denominator_inverses: Vec<u32>,
    ext_sources: Vec<ExtSource>,
    program: OwnedMetalEvaluationProgramV1,
}

impl CapturedComponent {
    pub fn new<E: FrameworkEval>(
        label: &str,
        instance: u32,
        component: &FrameworkComponent<E>,
        random_coefficient_offset: usize,
        program: OwnedMetalEvaluationProgramV1,
        ext_sources: Vec<ExtSource>,
    ) -> Result<Self> {
        let trace_log_size = component.evaluator().log_size();
        let evaluation_log_size = component.max_constraint_log_degree_bound();
        ensure!(
            evaluation_log_size >= trace_log_size,
            "{label}: evaluation domain is smaller than trace domain"
        );
        ensure!(
            program.header().n_base_params == 0,
            "{label}: base parameters require an explicit source model"
        );
        ensure!(
            program.header().n_ext_params as usize == ext_sources.len(),
            "{label}: extension source count differs from program ABI"
        );
        Ok(Self {
            label: label.to_owned(),
            instance,
            trace_log_size,
            evaluation_log_size,
            n_constraints: u32::try_from(component.n_constraints())?,
            random_coefficient_offset: u32::try_from(random_coefficient_offset)?,
            trace_spans: component
                .trace_locations()
                .iter()
                .map(|span| {
                    Ok((
                        u32::try_from(span.tree_index)?,
                        u32::try_from(span.col_start)?,
                        u32::try_from(span.col_end)?,
                    ))
                })
                .collect::<Result<_>>()?,
            preprocessed_indices: component
                .preprocessed_column_indices()
                .iter()
                .map(|index| u32::try_from(*index).map_err(Into::into))
                .collect::<Result<_>>()?,
            denominator_inverses: denominator_inverses(trace_log_size, evaluation_log_size),
            ext_sources,
            program,
        })
    }
}

pub fn encode(components: &[CapturedComponent]) -> Result<Vec<u8>> {
    ensure!(
        !components.is_empty(),
        "cannot encode an empty Cairo AIR bundle"
    );
    let total_constraints = components
        .iter()
        .map(|component| u64::from(component.n_constraints))
        .sum::<u64>();
    let max_evaluation_log_size = components
        .iter()
        .map(|component| component.evaluation_log_size)
        .max()
        .unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    push_u32(&mut bytes, VERSION);
    push_u32(&mut bytes, MAX_KERNEL_INSTRUCTIONS);
    push_u64(&mut bytes, total_constraints);
    push_u32(&mut bytes, max_evaluation_log_size);
    push_u32(&mut bytes, u32::try_from(components.len())?);
    push_u64(&mut bytes, 0);
    for component in components {
        encode_component(&mut bytes, component)?;
    }
    let plan_hash = fnv1a_with_zeroed_plan_hash(&bytes);
    bytes[PLAN_HASH_OFFSET..PLAN_HASH_OFFSET + 8].copy_from_slice(&plan_hash.to_le_bytes());
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("refusing to replace {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn encode_component(bytes: &mut Vec<u8>, component: &CapturedComponent) -> Result<()> {
    let label = component.label.as_bytes();
    push_u16(bytes, u16::try_from(label.len())?);
    push_u16(bytes, 0);
    push_u32(bytes, component.instance);
    push_u32(bytes, component.trace_log_size);
    push_u32(bytes, component.evaluation_log_size);
    push_u32(bytes, component.n_constraints);
    push_u32(bytes, component.random_coefficient_offset);
    push_u32(bytes, u32::try_from(component.trace_spans.len())?);
    push_u32(bytes, u32::try_from(component.preprocessed_indices.len())?);
    push_u32(bytes, u32::try_from(component.denominator_inverses.len())?);
    push_u32(bytes, u32::try_from(component.ext_sources.len())?);
    push_u32(bytes, 1);
    bytes.extend_from_slice(label);
    for (tree, start, end) in &component.trace_spans {
        push_u32(bytes, *tree);
        push_u32(bytes, *start);
        push_u32(bytes, *end);
    }
    for index in &component.preprocessed_indices {
        push_u32(bytes, *index);
    }
    for value in &component.denominator_inverses {
        push_u32(bytes, *value);
    }
    for source in &component.ext_sources {
        encode_ext_source(bytes, *source);
    }
    let program = encode_program(&component.program)?;
    push_u32(bytes, 0);
    push_u32(bytes, u32::try_from(program.len())?);
    push_u64(bytes, component.program.header().semantic_hash);
    bytes.extend_from_slice(&program);
    Ok(())
}

fn encode_ext_source(bytes: &mut Vec<u8>, source: ExtSource) {
    let (tag, power, scale) = match source {
        ExtSource::LookupZ => (1, 0, 0),
        ExtSource::LookupAlphaPower(power) => (2, power, 0),
        ExtSource::ClaimedSumScaled => (3, 0, 0),
        ExtSource::LookupAlphaPowerScaled { power, scale } => (4, power, scale.0),
    };
    push_u32(bytes, tag);
    push_u32(bytes, power);
    push_u32(bytes, scale);
    push_u32(bytes, 0);
    for _ in 0..4 {
        push_u32(bytes, 0);
    }
}

fn denominator_inverses(trace_log_size: u32, evaluation_log_size: u32) -> Vec<u32> {
    let trace_domain = CanonicCoset::new(trace_log_size);
    let evaluation_domain = CanonicCoset::new(evaluation_log_size).circle_domain();
    let mut values = (0..1usize << (evaluation_log_size - trace_log_size))
        .map(|index| {
            coset_vanishing(trace_domain.coset(), evaluation_domain.at(index))
                .inverse()
                .0
        })
        .collect::<Vec<_>>();
    bit_reverse(&mut values);
    values
}

fn fnv1a_with_zeroed_plan_hash(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for (index, byte) in bytes.iter().enumerate() {
        let value = if (PLAN_HASH_OFFSET..PLAN_HASH_OFFSET + 8).contains(&index) {
            0
        } else {
            *byte
        };
        hash ^= u64::from(value);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}
