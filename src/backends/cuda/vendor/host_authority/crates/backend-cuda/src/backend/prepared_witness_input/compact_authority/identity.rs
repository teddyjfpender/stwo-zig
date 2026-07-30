use super::*;

pub(super) fn require_canonical(
    requirements: &WitnessInputCompactRequirements,
) -> Result<(), WitnessInputCompactAuthorityError> {
    let edges = requirements
        .edges
        .iter()
        .map(|plan| plan.edge)
        .collect::<Vec<_>>();
    let expected =
        witness_input_compact_requirements(&edges, requirements.layout, requirements.consumer_rows)
            .map_err(map_requirements_error)?;
    if expected == *requirements {
        Ok(())
    } else {
        Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements)
    }
}

fn map_requirements_error(
    error: PreparedWitnessInputGatherError,
) -> WitnessInputCompactAuthorityError {
    match error {
        PreparedWitnessInputGatherError::ProducerRowsOverflow(_)
        | PreparedWitnessInputGatherError::InputWidthOverflow(_)
        | PreparedWitnessInputGatherError::WordBaseOverflow(_)
        | PreparedWitnessInputGatherError::InstanceCountOverflow(_)
        | PreparedWitnessInputGatherError::SizeOverflow
        | PreparedWitnessInputGatherError::TotalRowsOverflow => {
            WitnessInputCompactAuthorityError::SizeOverflow
        }
        _ => WitnessInputCompactAuthorityError::InvalidCanonicalRequirements,
    }
}

pub(super) fn descriptor_words(
    requirements: &WitnessInputCompactRequirements,
) -> Result<Vec<u32>, WitnessInputCompactAuthorityError> {
    let mut words = Vec::new();
    words
        .try_reserve_exact(requirements.descriptor_words)
        .map_err(|_| WitnessInputCompactAuthorityError::SizeOverflow)?;
    for plan in &requirements.edges {
        words.extend([
            u32_value(plan.edge.producer_rows)?,
            u32_value(plan.edge.word_base)?,
            u32_value(plan.edge.words_per_instance)?,
            u32_value(plan.edge.n_instances)?,
            u32_value(plan.destination_row_offset)?,
        ]);
    }
    let expected = requirements
        .edges
        .len()
        .checked_mul(WITNESS_INPUT_GATHER_DESCRIPTOR_WORDS)
        .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
    if words.len() == expected && words.len() == requirements.descriptor_words {
        Ok(words)
    } else {
        Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements)
    }
}

pub(super) fn fixed_words(
    requirements: &WitnessInputCompactRequirements,
) -> Result<[u32; 10], WitnessInputCompactAuthorityError> {
    let layout = requirements.layout;
    Ok([
        u32_value(requirements.edges.len())?,
        u32_value(layout.tuple_words)?,
        u32_value(layout.key_words)?,
        u32_value(requirements.total_input_rows)?,
        u32_value(requirements.sort_rows)?,
        u32_value(requirements.consumer_rows)?,
        u32_value(layout.consumer_input_count)?,
        layout.enabler_slot.map_or(Ok(NO_SLOT), u32_value)?,
        layout.iota_slot.map_or(Ok(NO_SLOT), u32_value)?,
        u32_value(layout.multiplicity_slot)?,
    ])
}

pub(super) fn stages(
    requirements: &WitnessInputCompactRequirements,
) -> Result<
    (
        Vec<WitnessInputCompactStage>,
        WitnessInputCompactIndexBuffer,
    ),
    WitnessInputCompactAuthorityError,
> {
    let count = requirements
        .layout
        .tuple_words
        .checked_mul(2)
        .and_then(|count| count.checked_add(6))
        .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
    let mut stages = Vec::new();
    stages
        .try_reserve_exact(count)
        .map_err(|_| WitnessInputCompactAuthorityError::SizeOverflow)?;
    let sort_launch = kernel_launch(u32_value(requirements.sort_rows)?);
    let consumer_launch = kernel_launch(u32_value(requirements.consumer_rows)?);
    let total_launch = kernel_launch(u32_value(requirements.total_input_rows)?);
    push_kernel(
        &mut stages,
        WitnessInputCompactKernelStage::Gather,
        sort_launch,
    )?;

    let mut current = WitnessInputCompactIndexBuffer::A;
    let mut next = WitnessInputCompactIndexBuffer::B;
    for word in (0..requirements.layout.tuple_words).rev() {
        let word = u32_value(word)?;
        push_kernel(
            &mut stages,
            WitnessInputCompactKernelStage::ExtractKey {
                word,
                indices: current,
            },
            sort_launch,
        )?;
        push_cub(
            &mut stages,
            WitnessInputCompactCubStage::StableRadixSortPairs {
                word,
                keys_from: WitnessInputCompactKeyBuffer::A,
                keys_to: WitnessInputCompactKeyBuffer::B,
                indices_from: current,
                indices_to: next,
                begin_bit: 0,
                end_bit: 32,
            },
        )?;
        core::mem::swap(&mut current, &mut next);
    }
    push_kernel(
        &mut stages,
        WitnessInputCompactKernelStage::Heads { indices: current },
        sort_launch,
    )?;
    push_cub(&mut stages, WitnessInputCompactCubStage::InclusiveSum)?;
    push_kernel(
        &mut stages,
        WitnessInputCompactKernelStage::ClearOutput,
        consumer_launch,
    )?;
    push_kernel(
        &mut stages,
        WitnessInputCompactKernelStage::Scatter { indices: current },
        total_launch,
    )?;
    push_kernel(
        &mut stages,
        WitnessInputCompactKernelStage::Finalize,
        consumer_launch,
    )?;
    if stages.len() != count {
        return Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements);
    }
    Ok((stages, current))
}

fn kernel_launch(rows: u32) -> WitnessInputCompactKernelLaunch {
    WitnessInputCompactKernelLaunch {
        grid: [rows.div_ceil(BLOCK_THREADS), 1, 1],
        block: [BLOCK_THREADS, 1, 1],
        dynamic_shared_bytes: 0,
        cooperative: false,
        cluster: None,
    }
}

fn push_kernel(
    stages: &mut Vec<WitnessInputCompactStage>,
    stage: WitnessInputCompactKernelStage,
    launch: WitnessInputCompactKernelLaunch,
) -> Result<(), WitnessInputCompactAuthorityError> {
    stages.push(WitnessInputCompactStage {
        ordinal: u32_value(stages.len())?,
        execution: WitnessInputCompactExecution::Kernel { stage, launch },
    });
    Ok(())
}

fn push_cub(
    stages: &mut Vec<WitnessInputCompactStage>,
    stage: WitnessInputCompactCubStage,
) -> Result<(), WitnessInputCompactAuthorityError> {
    stages.push(WitnessInputCompactStage {
        ordinal: u32_value(stages.len())?,
        execution: WitnessInputCompactExecution::Cub {
            stage,
            library_managed_launch_geometry: true,
            ordered_on_wrapper_stream: true,
        },
    });
    Ok(())
}

pub(super) fn effect_geometry(
    requirements: &WitnessInputCompactRequirements,
) -> Result<WitnessInputCompactEffectGeometry, WitnessInputCompactAuthorityError> {
    let sources = requirements
        .edges
        .iter()
        .enumerate()
        .map(|(ordinal, plan)| {
            let read_start_words = plan
                .edge
                .word_base
                .checked_mul(plan.edge.producer_rows)
                .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
            let read_len_words = plan
                .edge
                .words_per_instance
                .checked_mul(plan.edge.n_instances)
                .and_then(|words| words.checked_mul(plan.edge.producer_rows))
                .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
            if read_start_words.checked_add(read_len_words) != Some(plan.required_source_words) {
                return Err(WitnessInputCompactAuthorityError::InvalidCanonicalRequirements);
            }
            Ok(WitnessInputCompactSourceEffect {
                source_ordinal: u32_value(ordinal)?,
                read_start_words,
                read_len_words,
            })
        })
        .collect::<Result<Vec<_>, WitnessInputCompactAuthorityError>>()?;
    let outputs = requirements
        .consumer_input_column_words
        .iter()
        .enumerate()
        .map(|(ordinal, &words)| {
            Ok(WitnessInputCompactOutputEffect {
                output_ordinal: u32_value(ordinal)?,
                write_start_words: 0,
                write_len_words: words,
            })
        })
        .collect::<Result<Vec<_>, WitnessInputCompactAuthorityError>>()?;
    Ok(WitnessInputCompactEffectGeometry {
        sources,
        descriptor_read_start_words: 0,
        descriptor_read_len_words: requirements.descriptor_words,
        outputs,
        total_rows: u32_value(requirements.total_input_rows)?,
        sort_rows: u32_value(requirements.sort_rows)?,
        consumer_rows: u32_value(requirements.consumer_rows)?,
        tuple_words: u32_value(requirements.layout.tuple_words)?,
        key_words: u32_value(requirements.layout.key_words)?,
        multiplicity_slot: u32_value(requirements.layout.multiplicity_slot)?,
        enabler_slot: requirements
            .layout
            .enabler_slot
            .map(u32_value)
            .transpose()?,
        iota_slot: requirements.layout.iota_slot.map(u32_value).transpose()?,
        rejects_equal_key_distinct_tuple: true,
        padding_source_unique_row: 0,
        padding_multiplicity: 0,
        scratch: WitnessInputCompactScratchEffect {
            tuple_words: requirements.tuple_scratch_words,
            sort_key_words_each: requirements.sort_key_words,
            sort_index_words_each: requirements.sort_index_words,
            run_words_each: requirements.run_words,
            unique_count_words: 1,
            sort_temp_capacity_words: requirements.sort_temp_words,
            scan_temp_capacity_words: requirements.scan_temp_words,
        },
    })
}

pub(super) fn linked_contract(
    contract: &WitnessInputCompactContract,
    binding: StaticBuildBinding,
    sort_temp_bytes: usize,
    scan_temp_bytes: usize,
) -> Result<WitnessInputCompactLinkedContract, WitnessInputCompactAuthorityError> {
    let sort_capacity = contract
        .requirements
        .sort_temp_words
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
    let scan_capacity = contract
        .requirements
        .scan_temp_words
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(WitnessInputCompactAuthorityError::SizeOverflow)?;
    if sort_temp_bytes == 0
        || scan_temp_bytes == 0
        || sort_temp_bytes > sort_capacity
        || scan_temp_bytes > scan_capacity
    {
        return Err(WitnessInputCompactAuthorityError::InvalidRuntimeScratch);
    }
    let mut scratch_hasher = blake3::Hasher::new();
    scratch_hasher.update(RUNTIME_SCRATCH_DOMAIN);
    for value in [
        sort_temp_bytes,
        scan_temp_bytes,
        sort_capacity,
        scan_capacity,
    ] {
        hash_size_raw(&mut scratch_hasher, value)?;
    }
    let runtime_scratch_identity = *scratch_hasher.finalize().as_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract.identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    hasher.update(&runtime_scratch_identity);
    Ok(WitnessInputCompactLinkedContract {
        contract_identity: contract.identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        sort_temp_bytes,
        scan_temp_bytes,
        runtime_scratch_identity,
        identity: *hasher.finalize().as_bytes(),
    })
}

pub(super) fn u32_value(value: usize) -> Result<u32, WitnessInputCompactAuthorityError> {
    u32::try_from(value).map_err(|_| WitnessInputCompactAuthorityError::SizeOverflow)
}

pub(super) fn requirements_identity(
    requirements: &WitnessInputCompactRequirements,
) -> Result<[u8; 32], WitnessInputCompactAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    hash_size(&mut hasher, requirements.edges.len())?;
    for plan in &requirements.edges {
        for value in [
            plan.edge.producer_rows,
            plan.edge.word_base,
            plan.edge.words_per_instance,
            plan.edge.n_instances,
            plan.destination_row_offset,
            plan.destination_rows,
            plan.required_source_words,
        ] {
            hash_size(&mut hasher, value)?;
        }
    }
    let layout = requirements.layout;
    for value in [
        layout.tuple_words,
        layout.key_words,
        layout.consumer_input_count,
        layout.multiplicity_slot,
    ] {
        hash_size(&mut hasher, value)?;
    }
    hash_option_size(&mut hasher, layout.enabler_slot)?;
    hash_option_size(&mut hasher, layout.iota_slot)?;
    for value in [
        requirements.total_input_rows,
        requirements.sort_rows,
        requirements.consumer_rows,
        requirements.source_pointer_words,
        requirements.descriptor_words,
        requirements.output_pointer_words,
        requirements.tuple_scratch_words,
        requirements.sort_key_words,
        requirements.sort_index_words,
        requirements.run_words,
        requirements.sort_temp_words,
        requirements.scan_temp_words,
        requirements.consumer_input_column_words.len(),
    ] {
        hash_size(&mut hasher, value)?;
    }
    for words in &requirements.consumer_input_column_words {
        hash_size(&mut hasher, *words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn descriptor_identity(words: &[u32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    for field in WITNESS_INPUT_GATHER_DESCRIPTOR_ORDER {
        hasher.update(&[field as u8]);
    }
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn fixed_identity(words: &[u32; 10]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    for field in WITNESS_INPUT_COMPACT_FIXED_ORDER {
        hasher.update(&[field as u8]);
    }
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn abi_identity(abi: WitnessInputCompactAbi) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    hasher.update(&[abi as u8]);
    hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
    for argument in abi.arguments() {
        hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
        hash_bytes(&mut hasher, argument.name.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn effect_identity(
    effect: WitnessInputCompactEffectAbi,
    row_domain: WitnessInputCompactRowDomain,
    geometry: &WitnessInputCompactEffectGeometry,
) -> Result<[u8; 32], WitnessInputCompactAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    hasher.update(&[effect as u8, row_domain as u8]);
    hash_size(&mut hasher, geometry.sources.len())?;
    for source in &geometry.sources {
        hasher.update(&source.source_ordinal.to_le_bytes());
        hash_size(&mut hasher, source.read_start_words)?;
        hash_size(&mut hasher, source.read_len_words)?;
    }
    hash_size(&mut hasher, geometry.descriptor_read_start_words)?;
    hash_size(&mut hasher, geometry.descriptor_read_len_words)?;
    hash_size(&mut hasher, geometry.outputs.len())?;
    for output in &geometry.outputs {
        hasher.update(&output.output_ordinal.to_le_bytes());
        hash_size(&mut hasher, output.write_start_words)?;
        hash_size(&mut hasher, output.write_len_words)?;
    }
    for value in [
        geometry.total_rows,
        geometry.sort_rows,
        geometry.consumer_rows,
        geometry.tuple_words,
        geometry.key_words,
        geometry.multiplicity_slot,
    ] {
        hasher.update(&value.to_le_bytes());
    }
    hash_option_u32(&mut hasher, geometry.enabler_slot);
    hash_option_u32(&mut hasher, geometry.iota_slot);
    hasher.update(&[u8::from(geometry.rejects_equal_key_distinct_tuple)]);
    hasher.update(&geometry.padding_source_unique_row.to_le_bytes());
    hasher.update(&geometry.padding_multiplicity.to_le_bytes());
    for value in [
        geometry.scratch.tuple_words,
        geometry.scratch.sort_key_words_each,
        geometry.scratch.sort_index_words_each,
        geometry.scratch.run_words_each,
        geometry.scratch.unique_count_words,
        geometry.scratch.sort_temp_capacity_words,
        geometry.scratch.scan_temp_capacity_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn launch_identity(
    stages: &[WitnessInputCompactStage],
    final_indices: WitnessInputCompactIndexBuffer,
) -> Result<[u8; 32], WitnessInputCompactAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    hash_size(&mut hasher, stages.len())?;
    for stage in stages {
        hasher.update(&stage.ordinal.to_le_bytes());
        match stage.execution {
            WitnessInputCompactExecution::Kernel { stage, launch } => {
                hasher.update(&[1]);
                hash_kernel_stage(&mut hasher, stage);
                hash_bytes(&mut hasher, stage.symbol().as_bytes());
                for value in launch.grid.into_iter().chain(launch.block) {
                    hasher.update(&value.to_le_bytes());
                }
                hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
                hasher.update(&[u8::from(launch.cooperative)]);
                hash_cluster(&mut hasher, launch.cluster);
            }
            WitnessInputCompactExecution::Cub {
                stage,
                library_managed_launch_geometry,
                ordered_on_wrapper_stream,
            } => {
                hasher.update(&[2]);
                hash_cub_stage(&mut hasher, stage);
                hash_bytes(&mut hasher, stage.api().as_bytes());
                hasher.update(&[
                    u8::from(library_managed_launch_geometry),
                    u8::from(ordered_on_wrapper_stream),
                ]);
            }
        }
    }
    hasher.update(&[final_indices as u8]);
    Ok(*hasher.finalize().as_bytes())
}

fn hash_kernel_stage(hasher: &mut blake3::Hasher, stage: WitnessInputCompactKernelStage) {
    match stage {
        WitnessInputCompactKernelStage::Gather => {
            hasher.update(&[1]);
        }
        WitnessInputCompactKernelStage::ExtractKey { word, indices } => {
            hasher.update(&[2]);
            hasher.update(&word.to_le_bytes());
            hasher.update(&[indices as u8]);
        }
        WitnessInputCompactKernelStage::Heads { indices } => {
            hasher.update(&[3, indices as u8]);
        }
        WitnessInputCompactKernelStage::ClearOutput => {
            hasher.update(&[4]);
        }
        WitnessInputCompactKernelStage::Scatter { indices } => {
            hasher.update(&[5, indices as u8]);
        }
        WitnessInputCompactKernelStage::Finalize => {
            hasher.update(&[6]);
        }
    }
}

fn hash_cub_stage(hasher: &mut blake3::Hasher, stage: WitnessInputCompactCubStage) {
    match stage {
        WitnessInputCompactCubStage::StableRadixSortPairs {
            word,
            keys_from,
            keys_to,
            indices_from,
            indices_to,
            begin_bit,
            end_bit,
        } => {
            hasher.update(&[
                1,
                keys_from as u8,
                keys_to as u8,
                indices_from as u8,
                indices_to as u8,
                begin_bit,
                end_bit,
            ]);
            hasher.update(&word.to_le_bytes());
        }
        WitnessInputCompactCubStage::InclusiveSum => {
            hasher.update(&[2]);
        }
    }
}

pub(super) fn source_identity(
    static_source: [u8; 32],
    wrapper_source: [u8; 32],
    sources: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source);
    hasher.update(&wrapper_source);
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn contract_identity(identities: [[u8; 32]; 7]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for identity in identities {
        hasher.update(&identity);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_bytes(&mut hasher, bytes);
    *hasher.finalize().as_bytes()
}

fn hash_cluster(hasher: &mut blake3::Hasher, cluster: Option<[u32; 3]>) {
    hasher.update(&[u8::from(cluster.is_some())]);
    for value in cluster.unwrap_or([0; 3]) {
        hasher.update(&value.to_le_bytes());
    }
}

fn hash_option_u32(hasher: &mut blake3::Hasher, value: Option<u32>) {
    hasher.update(&[u8::from(value.is_some())]);
    hasher.update(&value.unwrap_or_default().to_le_bytes());
}

fn hash_option_size(
    hasher: &mut blake3::Hasher,
    value: Option<usize>,
) -> Result<(), WitnessInputCompactAuthorityError> {
    hasher.update(&[u8::from(value.is_some())]);
    hash_size(hasher, value.unwrap_or_default())
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&u64::try_from(bytes.len()).unwrap().to_le_bytes());
    hasher.update(bytes);
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), WitnessInputCompactAuthorityError> {
    hash_size_raw(hasher, value)
}

fn hash_size_raw(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), WitnessInputCompactAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| WitnessInputCompactAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}
