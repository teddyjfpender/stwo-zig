use super::effects::*;
use super::*;

const BLOCK_THREADS: u32 = 256;
const FUSED_SHARED_BYTES: u32 = 24_560;
const QM31_SHARED_BYTES: u32 = BLOCK_THREADS * 16;
const M31_SHARED_BYTES: u32 = BLOCK_THREADS * 4;

pub(super) struct CompiledContract {
    pub(super) descriptor_words: Vec<u32>,
    pub(super) geometry_words: Vec<u32>,
    pub(super) eligibility_mask: [u32; RELATION_FUSED_MASK_WORDS],
    pub(super) instances: Vec<RelationExecutionInstance>,
    pub(super) values: Vec<RelationValueLayout>,
    pub(super) wrappers: [RelationWrapperExecution; 2],
}

pub(super) fn compile_contract(
    program: &RelationKernelProgram,
    requirements: &RelationGraphRequirements,
    mode: RelationLaunchMode,
    tail: RelationTailMode,
) -> Result<CompiledContract, RelationExecutionAuthorityError> {
    if mode != RelationLaunchMode::Fused {
        return Err(RelationExecutionAuthorityError::UnsupportedLaunchMode(mode));
    }
    if tail != RelationTailMode::Segmented {
        return Err(RelationExecutionAuthorityError::UnsupportedTailMode(tail));
    }
    program.validate()?;
    let expected = program.requirements_for_mode(RelationLaunchMode::Fused)?;
    if expected != *requirements {
        return Err(RelationExecutionAuthorityError::NonCanonicalRequirements);
    }
    if requirements.instances.is_empty() {
        return Err(RelationExecutionAuthorityError::EmptyExecution);
    }
    for (batch_index, batch) in program.batches.iter().enumerate() {
        if matches!(batch.source_layout, RelationSourceLayout::BlakeGInputs) {
            return Err(
                RelationExecutionAuthorityError::BlakeGRequiresSeparateAuthority {
                    batch: batch_index,
                },
            );
        }
        if !relation_batch_fused_eligible(batch) {
            return Err(
                RelationExecutionAuthorityError::FusedFallbackRequiresSeparateAuthority {
                    batch: batch_index,
                },
            );
        }
    }

    let instances = compile_instances(program, requirements)?;
    let descriptor_words = program.descriptor_words()?;
    let geometry_words = instances
        .iter()
        .flat_map(|instance| instance.geometry)
        .collect::<Vec<_>>();
    let eligibility_mask = fused_eligibility_mask(&vec![true; instances.len()])
        .ok_or(RelationExecutionAuthorityError::SizeOverflow)?;
    let values = compile_values(program, requirements, &instances)?;
    let wrappers = [
        compile_fused_body(program, requirements, &instances, eligibility_mask)?,
        compile_segmented_tail(requirements, &instances)?,
    ];
    Ok(CompiledContract {
        descriptor_words,
        geometry_words,
        eligibility_mask,
        instances,
        values,
        wrappers,
    })
}

fn compile_instances(
    program: &RelationKernelProgram,
    requirements: &RelationGraphRequirements,
) -> Result<Vec<RelationExecutionInstance>, RelationExecutionAuthorityError> {
    let mut output = Vec::with_capacity(requirements.instances.len());
    let mut descriptor_columns = 0usize;
    let mut descriptor_offsets = Vec::with_capacity(program.batches.len());
    for batch in &program.batches {
        descriptor_offsets.push(descriptor_columns);
        descriptor_columns = descriptor_columns
            .checked_add(batch.columns.len())
            .ok_or(RelationExecutionAuthorityError::SizeOverflow)?;
    }
    let mut pair_first = 0u32;
    let mut inverse_first = 0u32;
    let mut row_first = 0u32;
    for requirement in &requirements.instances {
        let batch = &program.batches[requirement.batch_index];
        let extent = batch.instances[requirement.instance_index];
        let RelationRowExtent::Exact {
            n_real_rows,
            padded_rows,
            source_offset_rows,
        } = extent
        else {
            return Err(RelationExecutionAuthorityError::UnresolvedBoundedRows {
                batch: requirement.batch_index,
                instance: requirement.instance_index,
            });
        };
        let columns = u32::try_from(batch.columns.len())
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
        let (geometry, next_pair, next_inverse, next_row) = relation_instance_geometry(
            pair_first,
            inverse_first,
            row_first,
            padded_rows,
            columns,
            n_real_rows,
            source_offset_rows,
        )?;
        output.push(RelationExecutionInstance {
            batch_index: u32::try_from(requirement.batch_index)
                .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?,
            instance_index: u32::try_from(requirement.instance_index)
                .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?,
            source_layout: batch.source_layout,
            n_real_rows,
            padded_rows,
            source_offset_rows,
            columns,
            source_pointer_count: u32::try_from(batch.source_layout.pointer_count()?)
                .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?,
            output_coordinate_count: columns
                .checked_mul(SECURE_FIELD_WORDS as u32)
                .ok_or(RelationExecutionAuthorityError::SizeOverflow)?,
            descriptor_word_offset: u32::try_from(
                descriptor_offsets[requirement.batch_index]
                    .checked_mul(DESCRIPTOR_WORDS)
                    .ok_or(RelationExecutionAuthorityError::SizeOverflow)?,
            )
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?,
            geometry,
        });
        pair_first = next_pair;
        inverse_first = next_inverse;
        row_first = next_row;
    }
    if pair_first != requirements.pair_blocks
        || inverse_first != requirements.fraction_inverse_blocks
        || row_first != requirements.fraction_chain_blocks
    {
        return Err(RelationExecutionAuthorityError::NonCanonicalRequirements);
    }
    Ok(output)
}

fn compile_values(
    program: &RelationKernelProgram,
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Result<Vec<RelationValueLayout>, RelationExecutionAuthorityError> {
    use RelationValueOwnership as Owner;
    let mut values = vec![
        layout(
            RelationValueRole::Descriptors,
            requirements.descriptor_words,
            1,
            Owner::PreparedMetadata,
        ),
        layout(
            RelationValueRole::AlphaPowers,
            requirements.alpha_words,
            1,
            Owner::TranscriptChallenge,
        ),
        layout(
            RelationValueRole::ChallengeZ,
            requirements.z_words,
            1,
            Owner::TranscriptChallenge,
        ),
        layout(
            RelationValueRole::InverseScratchUnused,
            requirements.inverse_words,
            SECURE_FIELD_WORDS,
            Owner::ReservedUnused,
        ),
        layout(
            RelationValueRole::ReductionPartials,
            requirements.reduction_words,
            SECURE_FIELD_WORDS,
            Owner::ExecutionScratch,
        ),
        layout(
            RelationValueRole::ScanBlockSums,
            requirements.reduction_words,
            SECURE_FIELD_WORDS,
            Owner::ExecutionScratch,
        ),
        layout(
            RelationValueRole::ScanEvalScratchUnused,
            requirements.scan_eval_words,
            1,
            Owner::ReservedUnused,
        ),
        layout(
            RelationValueRole::ScanTempScratchUnused,
            requirements.scan_temp_words,
            1,
            Owner::ReservedUnused,
        ),
        layout(
            RelationValueRole::ScanDescriptorsUnused,
            requirements.scan_descriptor_words,
            SECURE_FIELD_WORDS,
            Owner::ReservedUnused,
        ),
    ];
    let dispatch_words = instances
        .len()
        .checked_mul(POINTER_WORDS)
        .ok_or(RelationExecutionAuthorityError::SizeOverflow)?;
    for table in RELATION_POINTER_TABLE_ORDER {
        values.push(layout(
            RelationValueRole::DispatchPointers(table),
            dispatch_words,
            RELATION_POINTER_ALIGNMENT_WORDS,
            Owner::PreparedMetadata,
        ));
    }
    values.push(layout(
        RelationValueRole::Geometry,
        requirements.fraction_geometry_words,
        1,
        Owner::PreparedMetadata,
    ));
    for (contract, requirement) in instances.iter().zip(&requirements.instances) {
        let batch = usize::try_from(contract.batch_index)
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
        let instance = usize::try_from(contract.instance_index)
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
        let key = (contract.batch_index, contract.instance_index);
        values.push(layout(
            RelationValueRole::InstanceSourcePointers {
                batch: key.0,
                instance: key.1,
            },
            requirement.source_pointer_words,
            RELATION_POINTER_ALIGNMENT_WORDS,
            Owner::PreparedMetadata,
        ));
        let source_words = relation_source_word_extents(
            program.batches[batch].source_layout,
            contract.padded_rows,
        )?;
        for source in 0..contract.source_pointer_count {
            values.push(layout(
                RelationValueRole::InstanceSource {
                    batch: key.0,
                    instance: key.1,
                    source,
                },
                source_words[source as usize],
                1,
                Owner::ExternalSource,
            ));
        }
        values.push(layout(
            RelationValueRole::InstanceOutputPointers {
                batch: key.0,
                instance: key.1,
            },
            requirement.output_pointer_words,
            RELATION_POINTER_ALIGNMENT_WORDS,
            Owner::PreparedMetadata,
        ));
        for coordinate in 0..contract.output_coordinate_count {
            values.push(layout(
                RelationValueRole::OutputCoordinate {
                    batch: key.0,
                    instance: key.1,
                    coordinate,
                },
                requirement.output_coordinate_words,
                1,
                Owner::ExecutionOutput,
            ));
        }
        values.push(layout(
            RelationValueRole::DenominatorSentinelUnused {
                batch: key.0,
                instance: key.1,
            },
            requirement.denominator_words,
            SECURE_FIELD_WORDS,
            Owner::ReservedUnused,
        ));
        values.push(layout(
            RelationValueRole::ClaimedSum {
                batch: key.0,
                instance: key.1,
            },
            requirement.claimed_sum_words,
            SECURE_FIELD_WORDS,
            Owner::ExecutionOutput,
        ));
        let _ = instance;
    }
    Ok(values)
}

fn compile_fused_body(
    program: &RelationKernelProgram,
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
    mask: [u32; RELATION_FUSED_MASK_WORDS],
) -> Result<RelationWrapperExecution, RelationExecutionAuthorityError> {
    let n_instances = u32::try_from(instances.len())
        .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
    let invocation = invocation(
        RelationAbi::FusedBodyV1,
        vec![
            role(RelationValueRole::DispatchPointers(
                RelationPointerTableKind::Sources,
            )),
            role(RelationValueRole::DispatchPointers(
                RelationPointerTableKind::Descriptors,
            )),
            role(RelationValueRole::DispatchPointers(
                RelationPointerTableKind::Outputs,
            )),
            role(RelationValueRole::Geometry),
            RelationInvocationValue::U32(n_instances),
            RelationInvocationValue::U32(requirements.fraction_chain_blocks),
            role(RelationValueRole::AlphaPowers),
            RelationInvocationValue::U32(program.max_alpha_powers),
            role(RelationValueRole::ChallengeZ),
            RelationInvocationValue::HostMask(mask),
            RelationInvocationValue::OrderedStream,
        ],
    )?;
    let child = RelationKernelLaunch {
        symbol: "relation_fused_kernel",
        grid: [requirements.fraction_chain_blocks, 1, 1],
        block: [BLOCK_THREADS, 1, 1],
        cluster: None,
        dynamic_shared_bytes: FUSED_SHARED_BYTES,
        cooperative: false,
        arguments: kernel_arguments([
            (
                "source_tables",
                role_kernel(RelationValueRole::DispatchPointers(
                    RelationPointerTableKind::Sources,
                )),
            ),
            (
                "descriptors",
                role_kernel(RelationValueRole::DispatchPointers(
                    RelationPointerTableKind::Descriptors,
                )),
            ),
            (
                "output_tables",
                role_kernel(RelationValueRole::DispatchPointers(
                    RelationPointerTableKind::Outputs,
                )),
            ),
            ("geometry", role_kernel(RelationValueRole::Geometry)),
            ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
            ("alphas", role_kernel(RelationValueRole::AlphaPowers)),
            ("z_ptr", role_kernel(RelationValueRole::ChallengeZ)),
            ("mask", RelationKernelArgumentValue::Mask(mask)),
        ]),
        accesses: fused_accesses(program, requirements, instances)?,
    };
    Ok(wrapper(RelationAbi::FusedBodyV1, invocation, vec![child]))
}

fn compile_segmented_tail(
    requirements: &RelationGraphRequirements,
    instances: &[RelationExecutionInstance],
) -> Result<RelationWrapperExecution, RelationExecutionAuthorityError> {
    let n_instances = u32::try_from(instances.len())
        .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
    let scan_blocks = requirements
        .fraction_chain_blocks
        .checked_mul(SECURE_FIELD_WORDS as u32)
        .ok_or(RelationExecutionAuthorityError::SizeOverflow)?;
    let reduction_capacity = u32::try_from(requirements.reduction_words / SECURE_FIELD_WORDS)
        .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
    let scan_capacity = u32::try_from(requirements.reduction_words)
        .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?;
    if reduction_capacity != requirements.fraction_chain_blocks || scan_capacity != scan_blocks {
        return Err(RelationExecutionAuthorityError::NonCanonicalRequirements);
    }
    let invocation = invocation(
        RelationAbi::SegmentedTailV1,
        vec![
            role(RelationValueRole::DispatchPointers(
                RelationPointerTableKind::Outputs,
            )),
            role(RelationValueRole::DispatchPointers(
                RelationPointerTableKind::ClaimedSums,
            )),
            role(RelationValueRole::Geometry),
            RelationInvocationValue::U32(n_instances),
            RelationInvocationValue::U32(requirements.fraction_chain_blocks),
            role(RelationValueRole::ReductionPartials),
            RelationInvocationValue::U32(reduction_capacity),
            role(RelationValueRole::ScanBlockSums),
            RelationInvocationValue::U32(scan_capacity),
            RelationInvocationValue::OrderedStream,
        ],
    )?;
    let common = |symbol, grid, shared, arguments, accesses| RelationKernelLaunch {
        symbol,
        grid: [grid, 1, 1],
        block: [BLOCK_THREADS, 1, 1],
        cluster: None,
        dynamic_shared_bytes: shared,
        cooperative: false,
        arguments,
        accesses,
    };
    let children = vec![
        common(
            "reduce_coordinates_ragged_kernel",
            requirements.fraction_chain_blocks,
            QM31_SHARED_BYTES,
            kernel_arguments([
                (
                    "output_tables",
                    role_kernel(RelationValueRole::DispatchPointers(
                        RelationPointerTableKind::Outputs,
                    )),
                ),
                ("geometry", role_kernel(RelationValueRole::Geometry)),
                ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
                (
                    "partials",
                    role_kernel(RelationValueRole::ReductionPartials),
                ),
            ]),
            reduce_accesses(requirements, instances),
        ),
        common(
            "finalize_claimed_sums_ragged_kernel",
            n_instances,
            QM31_SHARED_BYTES,
            kernel_arguments([
                (
                    "claimed_sums",
                    role_kernel(RelationValueRole::DispatchPointers(
                        RelationPointerTableKind::ClaimedSums,
                    )),
                ),
                ("geometry", role_kernel(RelationValueRole::Geometry)),
                ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
                (
                    "partials",
                    role_kernel(RelationValueRole::ReductionPartials),
                ),
            ]),
            finalize_accesses(requirements, instances),
        ),
        common(
            "shift_scan_tiles_ragged_kernel",
            scan_blocks,
            M31_SHARED_BYTES,
            kernel_arguments([
                (
                    "output_tables",
                    role_kernel(RelationValueRole::DispatchPointers(
                        RelationPointerTableKind::Outputs,
                    )),
                ),
                (
                    "claimed_sums",
                    role_kernel(RelationValueRole::DispatchPointers(
                        RelationPointerTableKind::ClaimedSums,
                    )),
                ),
                ("geometry", role_kernel(RelationValueRole::Geometry)),
                ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
                ("block_sums", role_kernel(RelationValueRole::ScanBlockSums)),
            ]),
            shift_accesses(requirements, instances),
        ),
        common(
            "scan_block_totals_ragged_kernel",
            n_instances
                .checked_mul(SECURE_FIELD_WORDS as u32)
                .ok_or(RelationExecutionAuthorityError::SizeOverflow)?,
            0,
            kernel_arguments([
                ("block_sums", role_kernel(RelationValueRole::ScanBlockSums)),
                ("geometry", role_kernel(RelationValueRole::Geometry)),
                ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
            ]),
            scan_accesses(requirements),
        ),
        common(
            "add_scan_offsets_ragged_kernel",
            scan_blocks,
            0,
            kernel_arguments([
                (
                    "output_tables",
                    role_kernel(RelationValueRole::DispatchPointers(
                        RelationPointerTableKind::Outputs,
                    )),
                ),
                ("geometry", role_kernel(RelationValueRole::Geometry)),
                ("n_instances", RelationKernelArgumentValue::U32(n_instances)),
                ("block_sums", role_kernel(RelationValueRole::ScanBlockSums)),
            ]),
            add_offset_accesses(requirements, instances),
        ),
    ];
    Ok(wrapper(RelationAbi::SegmentedTailV1, invocation, children))
}

fn invocation(
    abi: RelationAbi,
    values: Vec<RelationInvocationValue>,
) -> Result<RelationInvocation, RelationExecutionAuthorityError> {
    if values.len() != abi.arguments().len() {
        return Err(RelationExecutionAuthorityError::ContractMismatch);
    }
    Ok(RelationInvocation {
        abi,
        arguments: abi
            .arguments()
            .iter()
            .zip(values)
            .map(|(argument, value)| RelationInvocationArgument {
                ordinal: argument.ordinal,
                name: argument.name,
                value,
            })
            .collect(),
    })
}

fn wrapper(
    abi: RelationAbi,
    invocation: RelationInvocation,
    children: Vec<RelationKernelLaunch>,
) -> RelationWrapperExecution {
    let accesses = children
        .iter()
        .flat_map(|child| child.accesses.iter().copied())
        .collect();
    RelationWrapperExecution {
        stage: abi.stage(),
        abi,
        invocation,
        partition: RelationPartitionAuthority::Monolithic,
        accesses,
        children,
    }
}

fn kernel_arguments<const N: usize>(
    values: [(&'static str, RelationKernelArgumentValue); N],
) -> Vec<RelationKernelArgument> {
    values
        .into_iter()
        .map(|(name, value)| RelationKernelArgument { name, value })
        .collect()
}

const fn role(role: RelationValueRole) -> RelationInvocationValue {
    RelationInvocationValue::Role(role)
}

const fn role_kernel(role: RelationValueRole) -> RelationKernelArgumentValue {
    RelationKernelArgumentValue::Role(role)
}

const fn layout(
    role: RelationValueRole,
    words: usize,
    alignment_words: usize,
    ownership: RelationValueOwnership,
) -> RelationValueLayout {
    RelationValueLayout {
        role,
        words,
        alignment_words,
        ownership,
    }
}
