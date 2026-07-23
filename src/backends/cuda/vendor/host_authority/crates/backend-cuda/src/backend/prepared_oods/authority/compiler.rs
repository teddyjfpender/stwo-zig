use stwo::core::poly::circle::CanonicCoset;

use super::identity::host_call_identity;
use super::*;

const BLOCK: u32 = 256;
const SECURE_BYTES: usize = SECURE_WORDS * WORD_BYTES;

pub(super) struct CompiledOodsContract {
    pub columns: Vec<OodsExecutionColumn>,
    pub fixed_offset_words: Vec<u32>,
    pub fixed_fold_words: Vec<u32>,
    pub fixed_output_index_words: Vec<u32>,
    pub fixed_descriptor_offset_words: Vec<u32>,
    pub values: Vec<OodsExecutionValueLayout>,
    pub invocation: OodsExecutionInvocation,
    pub accesses: Vec<OodsExecutionAccess>,
    pub host_calls: Vec<OodsExecutionHostCall>,
}

pub(super) fn compile_contract(
    config: OodsWorkspaceConfig,
    topologies: &[OodsColumnTopology<'_>],
    program: &OodsPassCollapseProgram,
) -> Result<CompiledOodsContract, OodsExecutionAuthorityError> {
    program.validate_against(config, topologies)?;
    if program.receipt().covered_evaluation_group_count
        != program.identity().evaluation_groups.len()
        || !program.receipt().dynamic_shared_admitted
    {
        return Err(OodsExecutionAuthorityError::ProgramMismatch);
    }
    let columns = canonical_columns(config, topologies);
    let samples = &program.identity().canonical_samples;
    validate_samples(&columns, samples)?;
    let requirements = program.collapsed_requirements();
    let fixed_offset_words = samples
        .iter()
        .flat_map(|sample| [sample.offset_point.x.0, sample.offset_point.y.0])
        .collect::<Vec<_>>();
    let fixed_fold_words = samples
        .iter()
        .map(|sample| {
            config
                .lifting_log_size
                .checked_sub(sample.evaluation_log_size)
                .ok_or(OodsExecutionAuthorityError::InvalidDescriptorCoverage)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fixed_output_index_words = samples
        .iter()
        .map(|sample| {
            u32::try_from(sample.output_index)
                .map_err(|_| OodsExecutionAuthorityError::SizeOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let fixed_descriptor_offset_words = program
        .identity()
        .evaluation_groups
        .iter()
        .map(|group| {
            u32::try_from(group.descriptor_offset)
                .map_err(|_| OodsExecutionAuthorityError::SizeOverflow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fixed_offset_words.len() != requirements.offset_point_words
        || fixed_fold_words.len() != requirements.fold_count_words
        || fixed_output_index_words.len() != requirements.output_index_words
        || fixed_descriptor_offset_words.is_empty()
        || fixed_descriptor_offset_words.len() > requirements.barycentric_scale_words
    {
        return Err(OodsExecutionAuthorityError::InvalidDescriptorCoverage);
    }
    let values = value_layouts(&columns, requirements, fixed_descriptor_offset_words.len())?;
    let invocation = invocation();
    let accesses = accesses(
        &columns,
        samples,
        requirements,
        fixed_descriptor_offset_words.len(),
    )?;
    let host_calls = host_calls(program)?;
    let child_launches = host_calls
        .iter()
        .try_fold(0usize, |sum, call| sum.checked_add(call.children.len()))
        .ok_or(OodsExecutionAuthorityError::SizeOverflow)?;
    if child_launches != program.receipt().collapsed_total_kernel_launches {
        return Err(OodsExecutionAuthorityError::ProgramMismatch);
    }
    Ok(CompiledOodsContract {
        columns,
        fixed_offset_words,
        fixed_fold_words,
        fixed_output_index_words,
        fixed_descriptor_offset_words,
        values,
        invocation,
        accesses,
        host_calls,
    })
}

fn canonical_columns(
    config: OodsWorkspaceConfig,
    topologies: &[OodsColumnTopology<'_>],
) -> Vec<OodsExecutionColumn> {
    let mask_step = CanonicCoset::new(config.mask_log_size).step();
    topologies
        .iter()
        .copied()
        .map(|topology| OodsExecutionColumn {
            source_log_size: topology.log_size,
            evaluation_log_size: topology.evaluation_log_size,
            source_kind: topology.source_kind,
            offset_points: (0..topology.masks.len())
                .map(|mask| topology.offset_point(mask_step, mask))
                .collect(),
        })
        .collect()
}

fn validate_samples(
    columns: &[OodsExecutionColumn],
    samples: &[OodsCanonicalSample],
) -> Result<(), OodsExecutionAuthorityError> {
    let mut seen = vec![Vec::new(); columns.len()];
    for sample in samples {
        let column = columns
            .get(sample.column_index)
            .ok_or(OodsExecutionAuthorityError::InvalidDescriptorCoverage)?;
        if sample.source_kind != column.source_kind
            || sample.source_log_size != column.source_log_size
            || sample.evaluation_log_size != column.evaluation_log_size
            || column.offset_points.get(sample.mask_index) != Some(&sample.offset_point)
        {
            return Err(OodsExecutionAuthorityError::InvalidDescriptorCoverage);
        }
        seen[sample.column_index].push(sample.mask_index);
    }
    if seen.iter().zip(columns).any(|(actual, column)| {
        let mut actual = actual.clone();
        actual.sort_unstable();
        actual != (0..column.offset_points.len()).collect::<Vec<_>>()
    }) {
        return Err(OodsExecutionAuthorityError::InvalidDescriptorCoverage);
    }
    Ok(())
}

fn value_layouts(
    columns: &[OodsExecutionColumn],
    requirements: &OodsWorkspaceRequirements,
    descriptor_offset_words: usize,
) -> Result<Vec<OodsExecutionValueLayout>, OodsExecutionAuthorityError> {
    let mut values = Vec::with_capacity(columns.len() + 15);
    values.push(layout(
        OodsExecutionValueRole::SourcePointers,
        requirements.source_pointer_words,
        OODS_POINTER_ALIGNMENT_WORDS,
        OodsExecutionValueOwnership::PreparedRelocation,
    )?);
    for (column, topology) in columns.iter().enumerate() {
        values.push(layout(
            OodsExecutionValueRole::Source {
                column: to_u32(column)?,
            },
            pow2(topology.source_log_size)?,
            1,
            OodsExecutionValueOwnership::ExternalSource,
        )?);
    }
    values.extend([
        layout(
            OodsExecutionValueRole::PointParameter,
            OODS_PARAMETER_WORDS,
            SECURE_WORDS,
            OodsExecutionValueOwnership::TranscriptChallenge,
        )?,
        layout(
            OodsExecutionValueRole::OffsetPoints,
            requirements.offset_point_words,
            1,
            OodsExecutionValueOwnership::PreparedMetadata,
        )?,
        layout(
            OodsExecutionValueRole::FoldCounts,
            requirements.fold_count_words,
            1,
            OodsExecutionValueOwnership::PreparedMetadata,
        )?,
        layout(
            OodsExecutionValueRole::OutputIndices,
            requirements.output_index_words,
            1,
            OodsExecutionValueOwnership::PreparedMetadata,
        )?,
        layout(
            OodsExecutionValueRole::CollapsedDescriptorOffsets,
            descriptor_offset_words,
            1,
            OodsExecutionValueOwnership::PreparedMetadata,
        )?,
        layout(
            OodsExecutionValueRole::FoldingFactors,
            requirements.factor_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionScratch,
        )?,
        layout(
            OodsExecutionValueRole::ScratchA,
            requirements.scratch_a_words,
            SECURE_WORDS,
            scratch_ownership(requirements),
        )?,
        layout(
            OodsExecutionValueRole::ScratchB,
            requirements.scratch_b_words,
            SECURE_WORDS,
            scratch_ownership(requirements),
        )?,
        layout(
            OodsExecutionValueRole::SamplePoints,
            requirements.sample_point_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionOutput,
        )?,
        layout(
            OodsExecutionValueRole::SampledValues,
            requirements.sampled_value_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionOutput,
        )?,
        layout(
            OodsExecutionValueRole::EvaluationPoints,
            requirements.evaluation_point_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionScratch,
        )?,
        layout(
            OodsExecutionValueRole::BarycentricNumerators,
            requirements.barycentric_numerator_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ReservedUnused,
        )?,
        layout(
            OodsExecutionValueRole::BarycentricWeights,
            requirements.barycentric_weight_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionScratch,
        )?,
        layout(
            OodsExecutionValueRole::BarycentricPartials,
            requirements.barycentric_partial_words,
            SECURE_WORDS,
            OodsExecutionValueOwnership::ExecutionScratch,
        )?,
    ]);
    Ok(values)
}

fn scratch_ownership(requirements: &OodsWorkspaceRequirements) -> OodsExecutionValueOwnership {
    if requirements.groups.is_empty() {
        OodsExecutionValueOwnership::ReservedUnused
    } else {
        OodsExecutionValueOwnership::ExecutionScratch
    }
}

fn layout(
    role: OodsExecutionValueRole,
    words: usize,
    alignment_words: usize,
    ownership: OodsExecutionValueOwnership,
) -> Result<OodsExecutionValueLayout, OodsExecutionAuthorityError> {
    if words == 0 || alignment_words == 0 || !alignment_words.is_power_of_two() {
        return Err(OodsExecutionAuthorityError::ProgramMismatch);
    }
    Ok(OodsExecutionValueLayout {
        role,
        words,
        alignment_words,
        ownership,
    })
}

fn invocation() -> OodsExecutionInvocation {
    let abi = OodsExecutionAbi::CollapsedMixedV1;
    let arguments = abi
        .arguments()
        .iter()
        .map(|argument| OodsExecutionInvocationArgument {
            ordinal: argument.ordinal,
            name: argument.name,
            value: match argument.access {
                OodsExecutionAbiAccess::ReadSourcePointerTable => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::SourcePointers)
                }
                OodsExecutionAbiAccess::ReadPointParameter => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::PointParameter)
                }
                OodsExecutionAbiAccess::ReadOffsetPoints => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::OffsetPoints)
                }
                OodsExecutionAbiAccess::ReadFoldCounts => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::FoldCounts)
                }
                OodsExecutionAbiAccess::ReadOutputIndices => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::OutputIndices)
                }
                OodsExecutionAbiAccess::ReadCollapsedDescriptorOffsets => {
                    OodsExecutionInvocationValue::Role(
                        OodsExecutionValueRole::CollapsedDescriptorOffsets,
                    )
                }
                OodsExecutionAbiAccess::ReadWriteFoldingFactors => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::FoldingFactors)
                }
                OodsExecutionAbiAccess::ReadWriteScratchA => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::ScratchA)
                }
                OodsExecutionAbiAccess::ReadWriteScratchB => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::ScratchB)
                }
                OodsExecutionAbiAccess::WriteSamplePoints => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::SamplePoints)
                }
                OodsExecutionAbiAccess::WriteSampledValues => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::SampledValues)
                }
                OodsExecutionAbiAccess::ReadWriteEvaluationPoints => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::EvaluationPoints)
                }
                OodsExecutionAbiAccess::ReservedBarycentricNumerators => {
                    OodsExecutionInvocationValue::Role(
                        OodsExecutionValueRole::BarycentricNumerators,
                    )
                }
                OodsExecutionAbiAccess::ReadWriteBarycentricWeights => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::BarycentricWeights)
                }
                OodsExecutionAbiAccess::ReadWriteBarycentricPartials => {
                    OodsExecutionInvocationValue::Role(OodsExecutionValueRole::BarycentricPartials)
                }
                OodsExecutionAbiAccess::OrderedExecutionStream => {
                    OodsExecutionInvocationValue::OrderedStream
                }
            },
        })
        .collect();
    OodsExecutionInvocation { abi, arguments }
}

fn accesses(
    columns: &[OodsExecutionColumn],
    samples: &[OodsCanonicalSample],
    requirements: &OodsWorkspaceRequirements,
    descriptor_offset_words: usize,
) -> Result<Vec<OodsExecutionAccess>, OodsExecutionAuthorityError> {
    let mut accesses = Vec::with_capacity(samples.len() + 14);
    for sample in samples {
        let column = columns
            .get(sample.column_index)
            .ok_or(OodsExecutionAuthorityError::InvalidDescriptorCoverage)?;
        accesses.push(access(
            OodsExecutionValueRole::Source {
                column: to_u32(sample.column_index)?,
            },
            OodsExecutionAccessKind::Read,
            pow2(column.source_log_size)?,
        ));
    }
    accesses.extend([
        access(
            OodsExecutionValueRole::PointParameter,
            OodsExecutionAccessKind::Read,
            OODS_PARAMETER_WORDS,
        ),
        access(
            OodsExecutionValueRole::OffsetPoints,
            OodsExecutionAccessKind::Read,
            requirements.offset_point_words,
        ),
        access(
            OodsExecutionValueRole::FoldCounts,
            OodsExecutionAccessKind::Read,
            requirements.fold_count_words,
        ),
        access(
            OodsExecutionValueRole::OutputIndices,
            OodsExecutionAccessKind::Read,
            requirements.output_index_words,
        ),
        access(
            OodsExecutionValueRole::CollapsedDescriptorOffsets,
            OodsExecutionAccessKind::Read,
            descriptor_offset_words,
        ),
        access(
            OodsExecutionValueRole::FoldingFactors,
            OodsExecutionAccessKind::Write,
            requirements.factor_words,
        ),
    ]);
    if !requirements.groups.is_empty() {
        accesses.extend([
            access(
                OodsExecutionValueRole::ScratchA,
                OodsExecutionAccessKind::Write,
                requirements.scratch_a_words,
            ),
            access(
                OodsExecutionValueRole::ScratchB,
                OodsExecutionAccessKind::Write,
                requirements.scratch_b_words,
            ),
        ]);
    }
    accesses.extend([
        access(
            OodsExecutionValueRole::SamplePoints,
            OodsExecutionAccessKind::Write,
            requirements.sample_point_words,
        ),
        access(
            OodsExecutionValueRole::SampledValues,
            OodsExecutionAccessKind::Write,
            requirements.sampled_value_words,
        ),
        access(
            OodsExecutionValueRole::EvaluationPoints,
            OodsExecutionAccessKind::Write,
            requirements.evaluation_point_words,
        ),
        access(
            OodsExecutionValueRole::BarycentricWeights,
            OodsExecutionAccessKind::Write,
            requirements.barycentric_weight_words,
        ),
        access(
            OodsExecutionValueRole::BarycentricPartials,
            OodsExecutionAccessKind::Write,
            requirements.barycentric_partial_words,
        ),
    ]);
    Ok(accesses)
}

const fn access(
    role: OodsExecutionValueRole,
    kind: OodsExecutionAccessKind,
    words: usize,
) -> OodsExecutionAccess {
    OodsExecutionAccess {
        role,
        kind,
        start_word: 0,
        words,
    }
}

fn host_calls(
    program: &OodsPassCollapseProgram,
) -> Result<Vec<OodsExecutionHostCall>, OodsExecutionAuthorityError> {
    let mut calls = Vec::new();
    for (group_index, group) in program.collapsed_requirements().groups.iter().enumerate() {
        push_call(
            &mut calls,
            "stwo_oods_derive_points_on",
            OodsExecutionHostCallKind::DeriveCoefficient {
                group: to_u32(group_index)?,
            },
            vec![derive_launch(group.sample_count)?],
        )?;
        push_call(
            &mut calls,
            "stwo_oods_eval_first_on",
            OodsExecutionHostCallKind::EvaluateFirst {
                group: to_u32(group_index)?,
            },
            vec![eval_first_launch(group)?],
        )?;
        coefficient_reductions(&mut calls, group_index, group)?;
    }
    for (cohort_index, cohort) in program.receipt().same_log_cohorts.iter().enumerate() {
        for (batch_index, batch) in cohort.batches.iter().enumerate() {
            let range = batch.first_group..batch.first_group + batch.group_count;
            for group_index in range.clone() {
                let group = program
                    .collapsed_requirements()
                    .evaluation_groups
                    .get(group_index)
                    .ok_or(OodsExecutionAuthorityError::ProgramMismatch)?;
                push_call(
                    &mut calls,
                    "stwo_oods_derive_points_on",
                    OodsExecutionHostCallKind::DeriveEvaluation {
                        group: to_u32(group_index)?,
                    },
                    vec![derive_launch(group.sample_count)?],
                )?;
            }
            push_call(
                &mut calls,
                "stwo_oods_barycentric_weights_collapsed_cohort_on",
                OodsExecutionHostCallKind::CollapsedWeights {
                    cohort: to_u32(cohort_index)?,
                    batch: to_u32(batch_index)?,
                    first_group: to_u32(batch.first_group)?,
                    group_count: to_u32(batch.group_count)?,
                },
                vec![collapsed_weight_launch(batch)?],
            )?;
            let weight_stride = checked_mul(pow2(batch.log_size)?, SECURE_WORDS)?;
            for (local_group, group_index) in range.enumerate() {
                let group = program
                    .collapsed_requirements()
                    .evaluation_groups
                    .get(group_index)
                    .ok_or(OodsExecutionAuthorityError::ProgramMismatch)?;
                push_call(
                    &mut calls,
                    "stwo_oods_barycentric_eval_many_on",
                    OodsExecutionHostCallKind::EvaluateMany {
                        group: to_u32(group_index)?,
                        cohort: to_u32(cohort_index)?,
                        batch: to_u32(batch_index)?,
                        local_group: to_u32(local_group)?,
                        weight_offset_words: checked_mul(local_group, weight_stride)?,
                    },
                    eval_many_launches(group)?,
                )?;
            }
        }
    }
    Ok(calls)
}

fn coefficient_reductions(
    calls: &mut Vec<OodsExecutionHostCall>,
    group_index: usize,
    group: &OodsLogGroupRequirements,
) -> Result<(), OodsExecutionAuthorityError> {
    let mut current = OodsExecutionScratch::A;
    let mut current_size = group.first_pass_blocks;
    let mut current_stride = group.first_pass_blocks;
    let mut next = OodsExecutionScratch::B;
    let mut factor_index = group.log_size.saturating_sub(10);
    let mut pass = 0usize;
    while current_size > 1 {
        let next_size = current_size.div_ceil(512);
        push_call(
            calls,
            "stwo_oods_eval_reduce_on",
            OodsExecutionHostCallKind::EvaluateReduce {
                group: to_u32(group_index)?,
                pass: to_u32(pass)?,
                input_size: to_u32(current_size)?,
                input_stride: to_u32(current_stride)?,
                factor_index,
                output_stride: to_u32(next_size)?,
                input: current,
                output: next,
            },
            vec![eval_reduce_launch(next_size, group.sample_count)?],
        )?;
        let consumed = current_size.ilog2().min(9);
        current = next;
        current_size = next_size;
        current_stride = next_size;
        next = match next {
            OodsExecutionScratch::A => OodsExecutionScratch::B,
            OodsExecutionScratch::B => OodsExecutionScratch::A,
        };
        if current_size > 1 {
            factor_index = factor_index
                .checked_sub(consumed)
                .ok_or(OodsExecutionAuthorityError::SizeOverflow)?;
        }
        pass = pass
            .checked_add(1)
            .ok_or(OodsExecutionAuthorityError::SizeOverflow)?;
    }
    push_call(
        calls,
        "stwo_oods_store_results_on",
        OodsExecutionHostCallKind::StoreCoefficient {
            group: to_u32(group_index)?,
            reduced_stride: to_u32(current_stride)?,
            reduced: current,
        },
        vec![store_launch(group.sample_count)?],
    )
}

fn push_call(
    calls: &mut Vec<OodsExecutionHostCall>,
    wrapper_symbol: &'static str,
    kind: OodsExecutionHostCallKind,
    children: Vec<OodsExecutionKernelLaunch>,
) -> Result<(), OodsExecutionAuthorityError> {
    let ordinal = to_u32(calls.len())?;
    let mut call = OodsExecutionHostCall {
        ordinal,
        wrapper_symbol,
        kind,
        children,
        identity: [0; 32],
    };
    call.identity = host_call_identity(&call)?;
    calls.push(call);
    Ok(())
}

fn derive_launch(
    sample_count: usize,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    launch(
        "derive_points_kernel",
        [ceil_div_u32(sample_count, BLOCK)?, 1, 1],
        [BLOCK, 1, 1],
        0,
    )
}

fn eval_first_launch(
    group: &OodsLogGroupRequirements,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    launch(
        "eval_first_kernel",
        [
            to_u32(group.first_pass_blocks)?,
            to_u32(group.sample_count)?,
            1,
        ],
        [BLOCK, 1, 1],
        checked_u32(512 * WORD_BYTES + BLOCK as usize * SECURE_BYTES)?,
    )
}

fn eval_reduce_launch(
    output_stride: usize,
    sample_count: usize,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    launch(
        "eval_reduce_kernel",
        [to_u32(output_stride)?, to_u32(sample_count)?, 1],
        [BLOCK, 1, 1],
        checked_u32(512 * SECURE_BYTES)?,
    )
}

fn store_launch(
    sample_count: usize,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    launch(
        "store_results_kernel",
        [ceil_div_u32(sample_count, BLOCK)?, 1, 1],
        [BLOCK, 1, 1],
        0,
    )
}

fn collapsed_weight_launch(
    batch: &OodsPassCollapseBatchReceipt,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    let size = pow2(batch.log_size)?;
    if size < 1024 {
        launch(
            "barycentric_weights_collapsed_small_kernel",
            [ceil_div_u32(size, BLOCK)?, to_u32(batch.group_count)?, 1],
            [BLOCK, 1, 1],
            checked_u32(4 * SECURE_BYTES)?,
        )
    } else {
        launch(
            "barycentric_weights_collapsed_1024_kernel",
            [to_u32(size / 1024)?, to_u32(batch.group_count)?, 1],
            [512, 1, 1],
            checked_u32(OODS_COLLAPSED_DYNAMIC_SHARED_BYTES)?,
        )
    }
}

fn eval_many_launches(
    group: &OodsEvaluationGroupRequirements,
) -> Result<Vec<OodsExecutionKernelLaunch>, OodsExecutionAuthorityError> {
    let shared = checked_u32(BLOCK as usize * SECURE_BYTES)?;
    Ok(vec![
        launch(
            "barycentric_eval_many_kernel",
            [
                to_u32(group.reduction_blocks)?,
                to_u32(group.sample_count)?,
                1,
            ],
            [BLOCK, 1, 1],
            shared,
        )?,
        launch(
            "barycentric_reduce_rows_kernel",
            [to_u32(group.sample_count)?, 1, 1],
            [BLOCK, 1, 1],
            shared,
        )?,
    ])
}

fn launch(
    symbol: &'static str,
    grid: [u32; 3],
    block: [u32; 3],
    dynamic_shared_bytes: u32,
) -> Result<OodsExecutionKernelLaunch, OodsExecutionAuthorityError> {
    if grid.contains(&0) || block.contains(&0) {
        return Err(OodsExecutionAuthorityError::ProgramMismatch);
    }
    Ok(OodsExecutionKernelLaunch {
        symbol,
        grid,
        block,
        cluster: None,
        dynamic_shared_bytes,
        cooperative: false,
    })
}

fn ceil_div_u32(value: usize, divisor: u32) -> Result<u32, OodsExecutionAuthorityError> {
    let divisor = divisor as usize;
    to_u32(value.div_ceil(divisor))
}

fn checked_mul(lhs: usize, rhs: usize) -> Result<usize, OodsExecutionAuthorityError> {
    lhs.checked_mul(rhs)
        .ok_or(OodsExecutionAuthorityError::SizeOverflow)
}

fn checked_u32(value: usize) -> Result<u32, OodsExecutionAuthorityError> {
    to_u32(value)
}

fn to_u32(value: usize) -> Result<u32, OodsExecutionAuthorityError> {
    u32::try_from(value).map_err(|_| OodsExecutionAuthorityError::SizeOverflow)
}
