use super::*;

const WRAPPER_SOURCE_DOMAIN: &[u8] = b"stwo-cuda-relation-wrapper-source-v1\0";
const SOURCE_DOMAIN: &[u8] = b"stwo-cuda-relation-execution-source-v1\0";
const PROGRAM_DOMAIN: &[u8] = b"stwo-cuda-relation-program-v1\0";
const REQUIREMENTS_DOMAIN: &[u8] = b"stwo-cuda-relation-requirements-v1\0";
const FIXED_DOMAIN: &[u8] = b"stwo-cuda-relation-fixed-v1\0";
const ABI_DOMAIN: &[u8] = b"stwo-cuda-relation-abi-v1\0";
const EFFECT_DOMAIN: &[u8] = b"stwo-cuda-relation-effect-v1\0";
const LAUNCH_DOMAIN: &[u8] = b"stwo-cuda-relation-launch-v1\0";
const CONTRACT_DOMAIN: &[u8] = b"stwo-cuda-relation-contract-v1\0";
const LINKED_DOMAIN: &[u8] = b"stwo-cuda-relation-linked-v1\0";

const BINDER_SOURCE: &[u8] = include_bytes!("../../relation_graph.rs");
const AUTHORITY_SOURCE: &[u8] = include_bytes!("../authority.rs");
const COMPILER_SOURCE: &[u8] = include_bytes!("compiler.rs");
const EFFECTS_SOURCE: &[u8] = include_bytes!("effects.rs");
const IDENTITY_SOURCE: &[u8] = include_bytes!("identity.rs");
const RAW_FFI_SOURCE: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/src/raw.rs");
const FUSED_SOURCE: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/relation_fused.cu");
const TAIL_SOURCE: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/relation_graph.cu");
const FUSED_HEADER: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/relation_fused.cuh");
const INVERSE_HEADER: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/batch_inverse.cuh");
const SCAN_HEADER: &[u8] =
    include_bytes!("../../../../../backend-cuda-kernels/cuda/relation_scan.cuh");
const FIELDS_HEADER: &[u8] = include_bytes!("../../../../../backend-cuda-kernels/cuda/fields.cuh");

pub(super) fn wrapper_source_identity() -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(WRAPPER_SOURCE_DOMAIN);
    for source in [
        FUSED_SOURCE,
        TAIL_SOURCE,
        FUSED_HEADER,
        INVERSE_HEADER,
        SCAN_HEADER,
        FIELDS_HEADER,
    ] {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn source_identity(
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source_identity);
    hasher.update(&wrapper_source_identity);
    for source in [
        BINDER_SOURCE,
        AUTHORITY_SOURCE,
        COMPILER_SOURCE,
        EFFECTS_SOURCE,
        IDENTITY_SOURCE,
        RAW_FFI_SOURCE,
    ] {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn validate_static_symbols() -> Result<(), RelationExecutionAuthorityError> {
    for (symbol, source) in [
        ("stwo_relation_fused_on", FUSED_SOURCE),
        ("relation_fused_kernel", FUSED_SOURCE),
        ("stwo_relation_tail_global_on", TAIL_SOURCE),
        ("reduce_coordinates_ragged_kernel", TAIL_SOURCE),
        ("finalize_claimed_sums_ragged_kernel", TAIL_SOURCE),
        ("shift_scan_tiles_ragged_kernel", TAIL_SOURCE),
        ("scan_block_totals_ragged_kernel", TAIL_SOURCE),
        ("add_scan_offsets_ragged_kernel", TAIL_SOURCE),
        ("stwo_relation_fused_on", RAW_FFI_SOURCE),
        ("stwo_relation_tail_global_on", RAW_FFI_SOURCE),
    ] {
        if !contains(source, symbol.as_bytes()) {
            return Err(RelationExecutionAuthorityError::MissingStaticSymbol(symbol));
        }
    }
    Ok(())
}

pub(super) fn program_identity(
    program: &RelationKernelProgram,
) -> Result<[u8; 32], RelationExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PROGRAM_DOMAIN);
    hasher.update(&program.relation_graph_hash.to_le_bytes());
    hash_size(&mut hasher, program.template_use_count)?;
    hasher.update(&program.max_alpha_powers.to_le_bytes());
    hash_size(&mut hasher, program.batches.len())?;
    for batch in &program.batches {
        hash_source_layout(&mut hasher, batch.source_layout);
        hash_size(&mut hasher, batch.columns.len())?;
        for column in &batch.columns {
            hash_size(&mut hasher, column.uses.len())?;
            for relation_use in &column.uses {
                for value in [
                    relation_use.tuple_kind as u32,
                    relation_use.tuple_arg,
                    relation_use.tuple_words,
                    relation_use.relation_id,
                    relation_use.multiplicity_kind as u32,
                    relation_use.multiplicity_arg,
                    relation_use.negative as u32,
                ] {
                    hasher.update(&value.to_le_bytes());
                }
            }
        }
        hash_size(&mut hasher, batch.instances.len())?;
        for extent in &batch.instances {
            match extent {
                RelationRowExtent::Exact {
                    n_real_rows,
                    padded_rows,
                    source_offset_rows,
                } => {
                    hasher.update(&[1]);
                    hash_u32s(
                        &mut hasher,
                        &[*n_real_rows, *padded_rows, *source_offset_rows],
                    );
                }
                RelationRowExtent::Bounded {
                    observed_rows,
                    max_rows,
                    padded_capacity,
                } => {
                    hasher.update(&[2]);
                    hash_u32s(&mut hasher, &[*observed_rows, *max_rows, *padded_capacity]);
                }
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn requirements_identity(
    requirements: &RelationGraphRequirements,
) -> Result<[u8; 32], RelationExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.descriptor_words,
        requirements.alpha_words,
        requirements.z_words,
        requirements.inverse_words,
        requirements.reduction_words,
        requirements.scan_eval_words,
        requirements.scan_temp_words,
        requirements.scan_descriptor_words,
        requirements.fraction_pointer_words,
        requirements.fraction_geometry_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    hash_u32s(
        &mut hasher,
        &[
            requirements.pair_blocks,
            requirements.fraction_inverse_blocks,
            requirements.fraction_chain_blocks,
        ],
    );
    hash_size(&mut hasher, requirements.instances.len())?;
    for instance in &requirements.instances {
        for value in [
            instance.batch_index,
            instance.instance_index,
            instance.source_pointer_words,
            instance.output_pointer_words,
            instance.output_coordinate_count,
            instance.output_coordinate_words,
            instance.output_words,
            instance.denominator_words,
            instance.claimed_sum_words,
        ] {
            hash_size(&mut hasher, value)?;
        }
        hasher.update(&instance.row_capacity.to_le_bytes());
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn fixed_identity(
    descriptors: &[u32],
    geometry: &[u32],
    mask: &[u32; RELATION_FUSED_MASK_WORDS],
    instances: &[RelationExecutionInstance],
    values: &[RelationValueLayout],
) -> Result<[u8; 32], RelationExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    hash_words(&mut hasher, descriptors)?;
    hash_words(&mut hasher, geometry)?;
    hash_words(&mut hasher, mask)?;
    hash_size(&mut hasher, instances.len())?;
    for instance in instances {
        hash_u32s(
            &mut hasher,
            &[
                instance.batch_index,
                instance.instance_index,
                instance.n_real_rows,
                instance.padded_rows,
                instance.source_offset_rows,
                instance.columns,
                instance.source_pointer_count,
                instance.output_coordinate_count,
                instance.descriptor_word_offset,
            ],
        );
        hash_source_layout(&mut hasher, instance.source_layout);
        hash_u32s(&mut hasher, &instance.geometry);
    }
    hash_size(&mut hasher, values.len())?;
    for value in values {
        hash_role(&mut hasher, value.role);
        hash_size(&mut hasher, value.words)?;
        hash_size(&mut hasher, value.alignment_words)?;
        hasher.update(&[value.ownership as u8]);
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn abi_identity(wrappers: &[RelationWrapperExecution; 2]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    for wrapper in wrappers {
        hasher.update(&[
            wrapper.stage as u8,
            wrapper.abi as u8,
            wrapper.invocation.abi as u8,
        ]);
        hash_bytes(&mut hasher, wrapper.abi.wrapper_symbol().as_bytes());
        let arguments = wrapper.abi.arguments();
        hasher.update(&(arguments.len() as u64).to_le_bytes());
        for argument in arguments {
            hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
            hash_bytes(&mut hasher, argument.name.as_bytes());
        }
        hasher.update(&(wrapper.invocation.arguments.len() as u64).to_le_bytes());
        for argument in &wrapper.invocation.arguments {
            hasher.update(&[argument.ordinal]);
            hash_bytes(&mut hasher, argument.name.as_bytes());
            hash_invocation_value(&mut hasher, argument.value);
        }
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn effect_identity(
    wrappers: &[RelationWrapperExecution; 2],
) -> Result<[u8; 32], RelationExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    for wrapper in wrappers {
        hasher.update(&[wrapper.stage as u8]);
        hash_size(&mut hasher, wrapper.accesses.len())?;
        for access in &wrapper.accesses {
            hash_access(&mut hasher, access)?;
        }
        hash_size(&mut hasher, wrapper.children.len())?;
        for child in &wrapper.children {
            hash_bytes(&mut hasher, child.symbol.as_bytes());
            hash_size(&mut hasher, child.accesses.len())?;
            for access in &child.accesses {
                hash_access(&mut hasher, access)?;
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

fn hash_access(
    hasher: &mut blake3::Hasher,
    access: &RelationAccess,
) -> Result<(), RelationExecutionAuthorityError> {
    hash_role(hasher, access.role);
    hasher.update(&[access.kind as u8]);
    hash_size(hasher, access.start_word)?;
    hash_size(hasher, access.words)?;
    Ok(())
}

pub(super) fn launch_identity(
    wrappers: &[RelationWrapperExecution; 2],
) -> Result<[u8; 32], RelationExecutionAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    for wrapper in wrappers {
        hasher.update(&[
            wrapper.stage as u8,
            wrapper.abi as u8,
            match wrapper.partition {
                RelationPartitionAuthority::Monolithic => 1,
            },
        ]);
        hash_size(&mut hasher, wrapper.children.len())?;
        for child in &wrapper.children {
            hash_bytes(&mut hasher, child.symbol.as_bytes());
            hash_u32s(&mut hasher, &child.grid);
            hash_u32s(&mut hasher, &child.block);
            hasher.update(&child.dynamic_shared_bytes.to_le_bytes());
            hasher.update(&[
                u8::from(child.cooperative),
                u8::from(child.cluster.is_some()),
            ]);
            if let Some(cluster) = child.cluster {
                hash_u32s(&mut hasher, &cluster);
            }
            hash_size(&mut hasher, child.arguments.len())?;
            for argument in &child.arguments {
                hash_bytes(&mut hasher, argument.name.as_bytes());
                hash_kernel_value(&mut hasher, argument.value);
            }
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn contract_identity(fields: [[u8; 32]; 7]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for field in fields {
        hasher.update(&field);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn linked_authority(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> RelationLinkedExecutionAuthority {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    RelationLinkedExecutionAuthority {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

fn hash_source_layout(hasher: &mut blake3::Hasher, layout: RelationSourceLayout) {
    match layout {
        RelationSourceLayout::LookupWords { words } => hash_u32s(hasher, &[1, words]),
        RelationSourceLayout::ProjectedColumns { columns } => hash_u32s(hasher, &[2, columns]),
        RelationSourceLayout::BlakeGInputs => hash_u32s(hasher, &[3, 0]),
        RelationSourceLayout::MemoryAddress { chunks } => hash_u32s(hasher, &[4, chunks]),
        RelationSourceLayout::MemoryBig { value_words } => hash_u32s(hasher, &[5, value_words]),
        RelationSourceLayout::MemorySmall { value_words } => hash_u32s(hasher, &[6, value_words]),
        RelationSourceLayout::BitwiseXor12 {
            multiplicity_columns,
        } => hash_u32s(hasher, &[7, multiplicity_columns]),
    }
}

fn hash_role(hasher: &mut blake3::Hasher, role: RelationValueRole) {
    match role {
        RelationValueRole::Descriptors => hash_u32s(hasher, &[1]),
        RelationValueRole::AlphaPowers => hash_u32s(hasher, &[2]),
        RelationValueRole::ChallengeZ => hash_u32s(hasher, &[3]),
        RelationValueRole::DispatchPointers(table) => hash_u32s(hasher, &[4, table as u32]),
        RelationValueRole::Geometry => hash_u32s(hasher, &[5]),
        RelationValueRole::InstanceSourcePointers { batch, instance } => {
            hash_u32s(hasher, &[6, batch, instance])
        }
        RelationValueRole::InstanceSource {
            batch,
            instance,
            source,
        } => hash_u32s(hasher, &[7, batch, instance, source]),
        RelationValueRole::InstanceOutputPointers { batch, instance } => {
            hash_u32s(hasher, &[8, batch, instance])
        }
        RelationValueRole::OutputCoordinate {
            batch,
            instance,
            coordinate,
        } => hash_u32s(hasher, &[9, batch, instance, coordinate]),
        RelationValueRole::DenominatorSentinelUnused { batch, instance } => {
            hash_u32s(hasher, &[10, batch, instance])
        }
        RelationValueRole::ClaimedSum { batch, instance } => {
            hash_u32s(hasher, &[11, batch, instance])
        }
        RelationValueRole::InverseScratchUnused => hash_u32s(hasher, &[12]),
        RelationValueRole::ReductionPartials => hash_u32s(hasher, &[13]),
        RelationValueRole::ScanBlockSums => hash_u32s(hasher, &[14]),
        RelationValueRole::ScanEvalScratchUnused => hash_u32s(hasher, &[15]),
        RelationValueRole::ScanTempScratchUnused => hash_u32s(hasher, &[16]),
        RelationValueRole::ScanDescriptorsUnused => hash_u32s(hasher, &[17]),
    }
}

fn hash_invocation_value(hasher: &mut blake3::Hasher, value: RelationInvocationValue) {
    match value {
        RelationInvocationValue::Role(role) => {
            hasher.update(&[1]);
            hash_role(hasher, role);
        }
        RelationInvocationValue::U32(value) => {
            hasher.update(&[2]);
            hasher.update(&value.to_le_bytes());
        }
        RelationInvocationValue::HostMask(mask) => {
            hasher.update(&[3]);
            hash_u32s(hasher, &mask);
        }
        RelationInvocationValue::OrderedStream => {
            hasher.update(&[4]);
        }
    }
}

fn hash_kernel_value(hasher: &mut blake3::Hasher, value: RelationKernelArgumentValue) {
    match value {
        RelationKernelArgumentValue::Role(role) => {
            hasher.update(&[1]);
            hash_role(hasher, role);
        }
        RelationKernelArgumentValue::U32(value) => {
            hasher.update(&[2]);
            hasher.update(&value.to_le_bytes());
        }
        RelationKernelArgumentValue::Mask(mask) => {
            hasher.update(&[3]);
            hash_u32s(hasher, &mask);
        }
    }
}

fn hash_words(
    hasher: &mut blake3::Hasher,
    words: &[u32],
) -> Result<(), RelationExecutionAuthorityError> {
    hash_size(hasher, words.len())?;
    hash_u32s(hasher, words);
    Ok(())
}

fn hash_u32s(hasher: &mut blake3::Hasher, values: &[u32]) {
    for value in values {
        hasher.update(&value.to_le_bytes());
    }
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), RelationExecutionAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| RelationExecutionAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn contains(source: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && source.windows(needle.len()).any(|window| window == needle)
}
