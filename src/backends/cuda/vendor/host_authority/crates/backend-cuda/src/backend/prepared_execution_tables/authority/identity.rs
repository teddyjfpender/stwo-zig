use super::*;

pub(super) fn require_canonical(
    requirements: &ExecutionTablesWorkspaceRequirements,
) -> Result<(), ExecutionTablesAuthorityError> {
    let expected = execution_tables_workspace_requirements(
        requirements.n_addrs,
        requirements.n_big,
        requirements.n_small,
    )
    .map_err(map_requirements_error)?;
    if expected != *requirements {
        return Err(ExecutionTablesAuthorityError::InvalidCanonicalRequirements);
    }
    for value in [
        requirements.n_addrs,
        requirements.n_big,
        requirements.n_small,
        requirements.big_column_words,
        requirements.small_column_words,
    ] {
        u32_value(value)?;
    }
    Ok(())
}

fn map_requirements_error(error: PreparedExecutionTablesError) -> ExecutionTablesAuthorityError {
    match error {
        PreparedExecutionTablesError::SizeOverflow => ExecutionTablesAuthorityError::SizeOverflow,
        _ => ExecutionTablesAuthorityError::InvalidCanonicalRequirements,
    }
}

pub(super) fn host_ingress(
    requirements: &ExecutionTablesWorkspaceRequirements,
) -> Result<ExecutionTablesHostIngressGeometry, ExecutionTablesAuthorityError> {
    Ok(ExecutionTablesHostIngressGeometry {
        fields: [
            ingress_field(
                ExecutionTablesHostIngressRole::RawAddressToId,
                ExecutionTablesHostIngressEncoding::RawU32,
                requirements.n_addrs,
                1,
                requirements.raw_addr_to_id_words,
            )?,
            ingress_field(
                ExecutionTablesHostIngressRole::F252Values,
                ExecutionTablesHostIngressEncoding::F252LittleEndianU32x8,
                requirements.n_big,
                8,
                requirements.raw_f252_words,
            )?,
            ingress_field(
                ExecutionTablesHostIngressRole::SmallValues,
                ExecutionTablesHostIngressEncoding::SmallU128LittleEndianU32x4,
                requirements.n_small,
                4,
                requirements.raw_small_words,
            )?,
        ],
    })
}

fn ingress_field(
    role: ExecutionTablesHostIngressRole,
    encoding: ExecutionTablesHostIngressEncoding,
    rows: usize,
    words_per_row: u32,
    arena_words: usize,
) -> Result<ExecutionTablesHostIngressField, ExecutionTablesAuthorityError> {
    Ok(ExecutionTablesHostIngressField {
        role,
        encoding,
        rows: u32_value(rows)?,
        words_per_row,
        copied_words: rows
            .checked_mul(words_per_row as usize)
            .ok_or(ExecutionTablesAuthorityError::SizeOverflow)?,
        arena_words,
    })
}

pub(super) fn stage_contract(
    stage: ExecutionTablesStage,
    requirements: &ExecutionTablesWorkspaceRequirements,
) -> Result<ExecutionTablesStageContract, ExecutionTablesAuthorityError> {
    let (abi, real_rows, column_rows) = match stage {
        ExecutionTablesStage::Big => (
            ExecutionTablesAbi::BigLe8To28V1,
            u32_value(requirements.n_big)?,
            u32_value(requirements.big_column_words)?,
        ),
        ExecutionTablesStage::Small => (
            ExecutionTablesAbi::SmallLe4To8V1,
            u32_value(requirements.n_small)?,
            u32_value(requirements.small_column_words)?,
        ),
    };
    let input_bits = stage.input_words() * 32;
    let emitted_low_bits = stage.output_limbs() * LIMB_BITS;
    let effect_geometry = ExecutionTablesStageEffect {
        stage,
        source_start_word: 0,
        source_read_words: (real_rows as usize)
            .checked_mul(stage.input_words() as usize)
            .ok_or(ExecutionTablesAuthorityError::SizeOverflow)?,
        input_words_per_row: stage.input_words(),
        real_rows,
        column_rows,
        emitted_low_bits,
        ignored_high_bits: input_bits - emitted_low_bits,
        zero_padding_start_row: real_rows,
        zero_padding_rows: column_rows - real_rows,
        output_writes: (0..stage.output_limbs())
            .map(|column_ordinal| ExecutionTablesColumnEffect {
                column_ordinal,
                write_start_word: 0,
                written_words: column_rows,
            })
            .collect(),
    };
    let grid_x = 1 + (column_rows - 1) / BLOCK_THREADS;
    Ok(ExecutionTablesStageContract {
        abi,
        effect: ExecutionTablesEffectAbi::ReadLeWordsWriteLowNineBitLimbsZeroPadV1,
        row_domain: ExecutionTablesRowDomain::RealPrefixThenZeroPaddingV1,
        effect_geometry,
        launch: ExecutionTablesKernelLaunch {
            stage,
            grid: [grid_x, 1, 1],
            block: [BLOCK_THREADS, 1, 1],
            dynamic_shared_bytes: 0,
            cooperative: false,
            cluster: None,
        },
    })
}

pub(super) fn requirements_identity(
    requirements: &ExecutionTablesWorkspaceRequirements,
) -> Result<[u8; 32], ExecutionTablesAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REQUIREMENTS_DOMAIN);
    for value in [
        requirements.n_addrs,
        requirements.n_big,
        requirements.n_small,
        requirements.raw_addr_to_id_words,
        requirements.raw_f252_words,
        requirements.raw_small_words,
        requirements.big_column_words,
        requirements.small_column_words,
        requirements.table_pointer_words,
        requirements.table_stride_words,
    ] {
        hash_size(&mut hasher, value)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn host_ingress_identity(
    geometry: &ExecutionTablesHostIngressGeometry,
) -> Result<[u8; 32], ExecutionTablesAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INGRESS_DOMAIN);
    for field in geometry.fields {
        hasher.update(&[field.role as u8, field.encoding as u8]);
        hasher.update(&field.rows.to_le_bytes());
        hasher.update(&field.words_per_row.to_le_bytes());
        hash_size(&mut hasher, field.copied_words)?;
        hash_size(&mut hasher, field.arena_words)?;
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn fixed_identity(words: &[u32; 8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FIXED_DOMAIN);
    for field in EXECUTION_TABLES_FIXED_ORDER {
        hasher.update(&[field as u8]);
    }
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn abi_identity(stages: &[ExecutionTablesStageContract; 2]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ABI_DOMAIN);
    for stage in stages {
        let abi = stage.abi;
        hasher.update(&[abi as u8, abi.stage() as u8]);
        hash_bytes(&mut hasher, abi.entry_symbol().as_bytes());
        hasher.update(&(abi.arguments().len() as u64).to_le_bytes());
        for argument in abi.arguments() {
            hasher.update(&[argument.ordinal, argument.kind as u8, argument.access as u8]);
            hash_bytes(&mut hasher, argument.name.as_bytes());
        }
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn effect_identity(
    stages: &[ExecutionTablesStageContract; 2],
) -> Result<[u8; 32], ExecutionTablesAuthorityError> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EFFECT_DOMAIN);
    for stage in stages {
        let geometry = &stage.effect_geometry;
        hasher.update(&[
            geometry.stage as u8,
            stage.effect as u8,
            stage.row_domain as u8,
        ]);
        hash_size(&mut hasher, geometry.source_start_word)?;
        hash_size(&mut hasher, geometry.source_read_words)?;
        for value in [
            geometry.input_words_per_row,
            geometry.real_rows,
            geometry.column_rows,
            geometry.emitted_low_bits,
            geometry.ignored_high_bits,
            geometry.zero_padding_start_row,
            geometry.zero_padding_rows,
        ] {
            hasher.update(&value.to_le_bytes());
        }
        hash_size(&mut hasher, geometry.output_writes.len())?;
        for output in &geometry.output_writes {
            hasher.update(&output.column_ordinal.to_le_bytes());
            hasher.update(&output.write_start_word.to_le_bytes());
            hasher.update(&output.written_words.to_le_bytes());
        }
    }
    Ok(*hasher.finalize().as_bytes())
}

pub(super) fn launch_identity(stages: &[ExecutionTablesStageContract; 2]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LAUNCH_DOMAIN);
    for stage in stages {
        let launch = stage.launch;
        hasher.update(&[launch.stage as u8, u8::from(launch.cooperative)]);
        for value in launch.grid.into_iter().chain(launch.block) {
            hasher.update(&value.to_le_bytes());
        }
        hasher.update(&launch.dynamic_shared_bytes.to_le_bytes());
        hasher.update(&[u8::from(launch.cluster.is_some())]);
        hash_bytes(&mut hasher, launch.symbol().as_bytes());
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn source_identity(
    static_source_identity: [u8; 32],
    wrapper_source_identity: [u8; 32],
    sources: &[&[u8]],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SOURCE_DOMAIN);
    hasher.update(&static_source_identity);
    hasher.update(&wrapper_source_identity);
    for source in sources {
        hash_bytes(&mut hasher, source);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn contract_identity(fields: [[u8; 32]; 7]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(CONTRACT_DOMAIN);
    for field in fields {
        hasher.update(&field);
    }
    *hasher.finalize().as_bytes()
}

pub(super) fn linked_contract(
    contract_identity: [u8; 32],
    binding: StaticBuildBinding,
) -> ExecutionTablesLinkedContract {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LINKED_DOMAIN);
    hasher.update(&contract_identity);
    hasher.update(&binding.identity);
    hasher.update(&binding.module_build_identity);
    hasher.update(&binding.static_build_source_identity);
    hasher.update(&binding.target_sm.to_le_bytes());
    hasher.update(&binding.sm_identity);
    ExecutionTablesLinkedContract {
        contract_identity,
        module_build_identity: binding.module_build_identity,
        static_build_source_identity: binding.static_build_source_identity,
        static_build_identity: binding.identity,
        target_sm: binding.target_sm,
        sm_identity: binding.sm_identity,
        identity: *hasher.finalize().as_bytes(),
    }
}

pub(super) fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hash_bytes(&mut hasher, bytes);
    *hasher.finalize().as_bytes()
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn hash_size(
    hasher: &mut blake3::Hasher,
    value: usize,
) -> Result<(), ExecutionTablesAuthorityError> {
    hasher.update(
        &u64::try_from(value)
            .map_err(|_| ExecutionTablesAuthorityError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn u32_value(value: usize) -> Result<u32, ExecutionTablesAuthorityError> {
    u32::try_from(value).map_err(|_| ExecutionTablesAuthorityError::SizeOverflow)
}
