use super::*;

pub(super) fn source_identity(
    commit: &CommitProgram,
    direct: &DirectRetainedB2nProgram,
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    let static_source = stwo_backend_cuda_kernels::static_cuda_source_identity();
    source_identity_from_parts(
        static_source,
        commit.identity().cache_key,
        direct.commit_cache_key(),
        &authority_sources(),
    )
}

pub(super) fn source_identity_from_parts(
    static_source: [u8; 32],
    commit_cache_key: u64,
    direct_cache_key: u64,
    sources: &[&[u8]],
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    if static_source == ZERO_IDENTITY {
        return Err(BaseCommitAuthorityError::MissingStaticSourceIdentity);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source);
    hash_size(&mut hasher, sources.len());
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    hasher.update(&commit_cache_key.to_le_bytes());
    hasher.update(&direct_cache_key.to_le_bytes());
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn authority_sources() -> [&'static [u8]; 21] {
    [
        AUTHORITY_SOURCE,
        ABI_AUTHORITY_SOURCE,
        COMPILER_AUTHORITY_SOURCE,
        EFFECT_AUTHORITY_SOURCE,
        EFFECT_VALIDATION_SOURCE,
        ENCODING_AUTHORITY_SOURCE,
        EXECUTION_AUTHORITY_SOURCE,
        EXECUTION_ARGUMENTS_SOURCE,
        INVOCATION_AUTHORITY_SOURCE,
        COMMIT_SOURCE,
        DIRECT_SOURCE,
        DIRECT_LAUNCH_SOURCE,
        PREPARED_COMMIT_BINDER_SOURCE,
        IN_PLACE_PLANNER_SOURCE,
        PROGRESSIVE_COMMIT_SOURCE,
        NTT_LEAF_FUSION_SOURCE,
        RAW_FFI_SOURCE,
        B2N_SOURCE,
        N2B_SOURCE,
        BLAKE_SOURCE,
        IN_PLACE_SOURCE,
    ]
}

pub(super) fn operation_source_identity(program: [u8; 32], abi: BaseCommitAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&program);
    hasher.update(&[abi.tag()]);
    hasher.update(abi.wrapper_symbol().as_bytes());
    *hasher.finalize().as_bytes()
}

pub(super) fn operation_abi_identity(
    abi: BaseCommitAbi,
    kind: &BaseCommitOperationKind,
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi.tag()]);
    hash_bytes(&mut hasher, abi.wrapper_symbol().as_bytes());
    hash_size(&mut hasher, abi.arguments().len());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    hash_operation(&mut hasher, kind)?;
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn launch_identity(
    abi: BaseCommitAbi,
    kind: &BaseCommitOperationKind,
    execution: &[BaseCommitExecutionStep],
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hasher.update(&[abi.tag()]);
    hash_operation(&mut hasher, kind)?;
    hash_size(&mut hasher, execution.len());
    for step in execution {
        match step {
            BaseCommitExecutionStep::KernelLaunch(launch) => {
                hasher.update(&[0]);
                hash_bytes(&mut hasher, launch.symbol.as_bytes());
                for value in launch.grid.into_iter().chain(launch.block) {
                    hash_u32(&mut hasher, value);
                }
                match launch.cluster {
                    Some(cluster) => {
                        hasher.update(&[1]);
                        for value in cluster {
                            hash_u32(&mut hasher, value);
                        }
                    }
                    None => {
                        hasher.update(&[0]);
                    }
                }
                hash_u32(&mut hasher, launch.dynamic_shared_bytes);
                hasher.update(&[u8::from(launch.cooperative)]);
                hash_size(&mut hasher, launch.arguments.len());
                for argument in &launch.arguments {
                    hash_bytes(&mut hasher, argument.name.as_bytes());
                    match argument.value {
                        BaseCommitKernelArgumentValue::Buffer(buffer) => {
                            hasher.update(&[1]);
                            hash_execution_buffer(&mut hasher, buffer);
                        }
                        BaseCommitKernelArgumentValue::U32(value) => {
                            hasher.update(&[2]);
                            hash_u32(&mut hasher, value);
                        }
                        BaseCommitKernelArgumentValue::M31(value) => {
                            hasher.update(&[3]);
                            hash_u32(&mut hasher, value);
                        }
                        BaseCommitKernelArgumentValue::Null => {
                            hasher.update(&[4]);
                        }
                    }
                }
            }
            BaseCommitExecutionStep::DeviceCopyD2D {
                source,
                destination,
                bytes,
            } => {
                hasher.update(&[1]);
                hash_execution_buffer(&mut hasher, *source);
                hash_execution_buffer(&mut hasher, *destination);
                hasher.update(&bytes.to_le_bytes());
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_execution_buffer(hasher: &mut blake3::Hasher, buffer: BaseCommitExecutionBuffer) {
    match buffer {
        BaseCommitExecutionBuffer::WrapperArgument {
            ordinal,
            byte_offset,
        } => {
            hasher.update(&[1, ordinal]);
            hasher.update(&byte_offset.to_le_bytes());
        }
        BaseCommitExecutionBuffer::DependencySuffix { role, byte_offset } => {
            hasher.update(&[2]);
            hash_dependency_role(hasher, role);
            hasher.update(&byte_offset.to_le_bytes());
        }
    }
}

fn hash_dependency_role(hasher: &mut blake3::Hasher, role: BaseCommitDependencyRole) {
    match role {
        BaseCommitDependencyRole::BatchSourcePointerTable { batch_index } => {
            hasher.update(&[1]);
            hash_u32(hasher, batch_index);
        }
        BaseCommitDependencyRole::BatchRetainedPointerTable { batch_index } => {
            hasher.update(&[2]);
            hash_u32(hasher, batch_index);
        }
        BaseCommitDependencyRole::InverseTwiddles => {
            hasher.update(&[3]);
        }
        BaseCommitDependencyRole::ForwardTwiddles => {
            hasher.update(&[4]);
        }
        BaseCommitDependencyRole::InPlaceScratch => {
            hasher.update(&[5]);
        }
    }
}

pub(super) fn operation_identity(
    source: [u8; 32],
    abi: [u8; 32],
    effect: [u8; 32],
    invocation: [u8; 32],
    launch: [u8; 32],
    partition: &BaseCommitPartitionAuthority,
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(OPERATION_DOMAIN);
    hasher.update(&source);
    hasher.update(&abi);
    hasher.update(&effect);
    hasher.update(&invocation);
    hasher.update(&launch);
    hash_partition(&mut hasher, partition)?;
    Ok(*hasher.finalize().as_bytes())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn program_identity(
    commit: &CommitProgram,
    direct: &DirectRetainedB2nProgram,
    source: [u8; 32],
    layouts: &[BaseCommitLayout],
    operations: &[BaseCommitOperation],
    evaluations: &[BaseCommitRetainedEvaluation],
    layers: &[BaseCommitRetainedLayer],
    root: BaseCommitValueRole,
) -> Result<[u8; 32], BaseCommitAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROGRAM_DOMAIN);
    hasher.update(&commit.identity().cache_key.to_le_bytes());
    hasher.update(&direct.commit_cache_key().to_le_bytes());
    hasher.update(&source);
    hash_size(&mut hasher, layouts.len());
    for layout in layouts {
        hash_role(&mut hasher, layout.role);
        for value in [
            layout.rows,
            layout.words_per_row,
            layout.logical_words,
            layout.alignment_words,
        ] {
            hash_size(&mut hasher, value);
        }
    }
    hash_size(&mut hasher, operations.len());
    for operation in operations {
        hasher.update(&operation.identity);
    }
    hash_size(&mut hasher, evaluations.len());
    for evaluation in evaluations {
        hasher.update(&evaluation.canonical_column.to_le_bytes());
        hash_role(&mut hasher, evaluation.role);
        hash_size(&mut hasher, evaluation.words);
    }
    hash_size(&mut hasher, layers.len());
    for layer in layers {
        hasher.update(&layer.log_size.to_le_bytes());
        hash_role(&mut hasher, layer.role);
        hash_size(&mut hasher, layer.words);
    }
    hash_role(&mut hasher, root);
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn linked_authority(
    program_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> BaseCommitLinkedAuthority {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&program_identity);
    hasher.update(&binding.identity);
    BaseCommitLinkedAuthority {
        program_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn hash_partition(
    hasher: &mut blake3::Hasher,
    partition: &BaseCommitPartitionAuthority,
) -> Result<(), BaseCommitAuthorityError> {
    match partition {
        BaseCommitPartitionAuthority::Monolithic => {
            hasher.update(&[0]);
        }
    }
    Ok(())
}

pub(super) fn hash_operation(
    hasher: &mut blake3::Hasher,
    operation: &BaseCommitOperationKind,
) -> Result<(), BaseCommitAuthorityError> {
    match operation {
        BaseCommitOperationKind::DirectB2n {
            batch_index,
            segment_offset,
            source_log_size,
            retained_log_size,
            canonical_columns,
        } => {
            hasher.update(&[1]);
            hash_u32(hasher, *batch_index);
            hash_u32(hasher, *segment_offset);
            hash_u32(hasher, *source_log_size);
            hash_u32(hasher, *retained_log_size);
            hash_u32_slice(hasher, canonical_columns);
        }
        BaseCommitOperationKind::DirectN2b {
            batch_index,
            segment_offset,
            source_log_size,
            retained_log_size,
            canonical_columns,
        } => {
            hasher.update(&[2]);
            hash_u32(hasher, *batch_index);
            hash_u32(hasher, *segment_offset);
            hash_u32(hasher, *source_log_size);
            hash_u32(hasher, *retained_log_size);
            hash_u32_slice(hasher, canonical_columns);
        }
        BaseCommitOperationKind::StateInit { log_size } => {
            hasher.update(&[3]);
            hash_u32(hasher, *log_size);
        }
        BaseCommitOperationKind::StateExpandInPlace {
            from_log_size,
            to_log_size,
            absorbed_columns,
            bands,
        } => {
            hasher.update(&[4]);
            hash_u32(hasher, *from_log_size);
            hash_u32(hasher, *to_log_size);
            hash_u32(hasher, *absorbed_columns);
            hash_u32(hasher, *bands);
        }
        BaseCommitOperationKind::StateAbsorb {
            batch_index,
            segment_offset,
            log_size,
            absorbed_columns_before,
            canonical_columns,
        } => {
            hasher.update(&[5]);
            hash_u32(hasher, *batch_index);
            hash_u32(hasher, *segment_offset);
            hash_u32(hasher, *log_size);
            hash_u32(hasher, *absorbed_columns_before);
            hash_u32_slice(hasher, canonical_columns);
        }
        BaseCommitOperationKind::StateFinalizeInPlace {
            log_size,
            absorbed_columns,
            bands,
        } => {
            hasher.update(&[6]);
            hash_u32(hasher, *log_size);
            hash_u32(hasher, *absorbed_columns);
            hash_u32(hasher, *bands);
        }
        BaseCommitOperationKind::MerkleLayerInPlace {
            level,
            output_hashes,
            bands,
        } => {
            hasher.update(&[7]);
            hash_u32(hasher, *level);
            hash_u32(hasher, *output_hashes);
            hash_u32(hasher, *bands);
        }
        BaseCommitOperationKind::MerkleLayer {
            level,
            output_hashes,
        } => {
            hasher.update(&[8]);
            hash_u32(hasher, *level);
            hash_u32(hasher, *output_hashes);
        }
    }
    Ok(())
}

pub(super) fn hash_role(hasher: &mut blake3::Hasher, role: BaseCommitValueRole) {
    match role {
        BaseCommitValueRole::SourceEvaluation { canonical_column } => {
            hasher.update(&[1]);
            hash_u32(hasher, canonical_column);
        }
        BaseCommitValueRole::RetainedStageTwo { canonical_column } => {
            hasher.update(&[2]);
            hash_u32(hasher, canonical_column);
        }
        BaseCommitValueRole::RetainedEvaluation { canonical_column } => {
            hasher.update(&[3]);
            hash_u32(hasher, canonical_column);
        }
        BaseCommitValueRole::State { version, log_size } => {
            hasher.update(&[4]);
            hash_u32(hasher, version);
            hash_u32(hasher, log_size);
        }
        BaseCommitValueRole::HashLayer { log_size } => {
            hasher.update(&[5]);
            hash_u32(hasher, log_size);
        }
    }
}

fn hash_u32(hasher: &mut blake3::Hasher, value: u32) {
    hasher.update(&value.to_le_bytes());
}

fn hash_u32_slice(hasher: &mut blake3::Hasher, values: &[u32]) {
    hash_size(hasher, values.len());
    for &value in values {
        hash_u32(hasher, value);
    }
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hash_size(hasher, bytes.len());
    hasher.update(bytes);
}

pub(super) fn hash_size(hasher: &mut blake3::Hasher, value: usize) {
    hasher.update(&(value as u64).to_le_bytes());
}
