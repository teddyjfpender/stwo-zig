use super::*;

mod arguments;

use arguments::*;

const MAX_NTT_BATCH_COLUMNS: u32 = 65_535;
const BLOCK_SIZE: u32 = 256;

const B2N_13_18: [[u32; 2]; 6] = [[7, 6], [8, 6], [7, 8], [8, 8], [9, 8], [10, 8]];
const B2N_19_24: [[u32; 3]; 6] = [
    [7, 6, 6],
    [8, 6, 6],
    [7, 6, 8],
    [8, 6, 8],
    [7, 8, 8],
    [8, 8, 8],
];
const B2N_25_29: [[u32; 4]; 5] = [
    [7, 6, 6, 6],
    [8, 6, 6, 6],
    [7, 8, 6, 6],
    [8, 8, 6, 6],
    [7, 8, 8, 6],
];

const N2B_13_19: [[u32; 2]; 7] = [[6, 7], [6, 8], [8, 7], [8, 8], [6, 11], [8, 10], [8, 11]];
const N2B_20_27: [[u32; 3]; 8] = [
    [6, 6, 8],
    [6, 8, 7],
    [6, 8, 8],
    [8, 8, 7],
    [8, 8, 8],
    [6, 8, 11],
    [8, 8, 10],
    [8, 8, 11],
];
const N2B_28_30: [[u32; 4]; 3] = [[6, 6, 6, 10], [6, 6, 6, 11], [6, 6, 8, 10]];

pub(super) fn execution_manifest(
    kind: &BaseCommitOperationKind,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    let steps = match kind {
        BaseCommitOperationKind::DirectB2n {
            source_log_size,
            canonical_columns,
            ..
        } => b2n_manifest(*source_log_size, count(canonical_columns.len())?)?,
        BaseCommitOperationKind::DirectN2b {
            retained_log_size,
            canonical_columns,
            ..
        } => n2b_manifest(*retained_log_size, count(canonical_columns.len())?)?,
        BaseCommitOperationKind::StateInit { log_size } => vec![kernel(
            "progressive_leaf_init_in_gpu",
            blocks(pow2(*log_size)?)?,
            BLOCK_SIZE,
            vec![
                u32_argument("size", pow2(*log_size)?),
                buffer_argument("states", wrapper_buffer(1, 0)),
            ],
        )],
        BaseCommitOperationKind::StateExpandInPlace {
            from_log_size,
            to_log_size,
            bands,
            ..
        } => expand_manifest(*from_log_size, *to_log_size, *bands)?,
        BaseCommitOperationKind::StateAbsorb {
            log_size,
            absorbed_columns_before,
            canonical_columns,
            ..
        } => {
            let size = pow2(*log_size)?;
            vec![kernel(
                "progressive_leaf_absorb_in_gpu",
                blocks(size)?,
                BLOCK_SIZE,
                vec![
                    u32_argument("size", size),
                    u32_argument("number_of_columns", count(canonical_columns.len())?),
                    u32_argument("absorbed_columns_before", *absorbed_columns_before),
                    buffer_argument("columns", wrapper_buffer(3, 0)),
                    buffer_argument("states", wrapper_buffer(4, 0)),
                ],
            )]
        }
        BaseCommitOperationKind::StateFinalizeInPlace {
            log_size,
            absorbed_columns,
            bands,
        } => finalize_manifest(*log_size, *absorbed_columns, *bands)?,
        BaseCommitOperationKind::MerkleLayerInPlace {
            output_hashes,
            bands,
            ..
        } => merkle_in_place_manifest(*output_hashes, *bands)?,
        BaseCommitOperationKind::MerkleLayer { output_hashes, .. } => {
            vec![kernel(
                "stwo_gpu_lab_blake2s_layer",
                blocks(*output_hashes)?,
                BLOCK_SIZE,
                merkle_arguments(*output_hashes, wrapper_buffer(0, 0), wrapper_buffer(2, 0)),
            )]
        }
    };
    validate_manifest(&steps)?;
    Ok(steps)
}

fn b2n_manifest(
    log_size: u32,
    columns: u32,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    if !(3..=29).contains(&log_size) || columns == 0 {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    let mut result = Vec::new();
    for (column_base, chunk) in column_chunks(columns) {
        if let Some(parts) = b2n_parts(log_size) {
            let mut start = 1;
            result.push(b2n_init(log_size, column_base, chunk, parts[0])?);
            start += parts[0];
            for (index, &stages) in parts.iter().enumerate().skip(1) {
                result.push(b2n_noinit(
                    log_size,
                    column_base,
                    chunk,
                    start,
                    stages,
                    index + 1 == parts.len(),
                )?);
                start += stages;
            }
        } else {
            let block = if log_size <= 8 {
                pow2(log_size - 1)?
            } else {
                128
            };
            let grid = if log_size <= 8 {
                1
            } else {
                pow2(log_size - 8)?
            };
            for stage in 1..=log_size {
                result.push(kernel_3d(
                    if stage == log_size {
                        "ntt_b2n_stage_batch<true>"
                    } else {
                        "ntt_b2n_stage_batch<false>"
                    },
                    [grid, chunk, 1],
                    [block, 1, 1],
                    b2n_stage_arguments(log_size, column_base, stage)?,
                ));
            }
        }
    }
    Ok(result)
}

fn b2n_parts(log_size: u32) -> Option<&'static [u32]> {
    match log_size {
        13..=18 => Some(&B2N_13_18[(log_size - 13) as usize]),
        19..=24 => Some(&B2N_19_24[(log_size - 19) as usize]),
        25..=29 => Some(&B2N_25_29[(log_size - 25) as usize]),
        _ => None,
    }
}

fn b2n_init(
    log_size: u32,
    column_base: u32,
    columns: u32,
    stages: u32,
) -> Result<BaseCommitExecutionStep, BaseCommitAuthorityError> {
    let (symbol, grid, block, max_stage) = match stages {
        7 | 8 => {
            let log_values = stages - 5;
            let warps = pow2(log_size - 5 - log_values)?;
            let block_y = warps.min(4);
            (
                if stages == 7 {
                    "b2n_init_warp_batch<2>"
                } else {
                    "b2n_init_warp_batch<3>"
                },
                [warps / block_y, columns, 1],
                [32, block_y, 1],
                stages,
            )
        }
        9 | 10 => {
            let log_warps = stages - 8;
            (
                if stages == 9 {
                    "b2n_init_block_warp_batch<1>"
                } else {
                    "b2n_init_block_warp_batch<2>"
                },
                [pow2(log_size - 8 - log_warps)?, 1, columns],
                [32, pow2(log_warps)?, 1],
                1 + stages,
            )
        }
        _ => return Err(BaseCommitAuthorityError::InvalidExecutionManifest),
    };
    Ok(kernel_3d(
        symbol,
        grid,
        block,
        b2n_interval_arguments(0, 1, log_size, column_base, columns, 1, max_stage, None)?,
    ))
}

fn b2n_noinit(
    log_size: u32,
    column_base: u32,
    columns: u32,
    start_stage: u32,
    stages: u32,
    duplicate: bool,
) -> Result<BaseCommitExecutionStep, BaseCommitAuthorityError> {
    let log_values = match stages {
        4 => 2,
        6 => 3,
        8 => 4,
        _ => return Err(BaseCommitAuthorityError::InvalidExecutionManifest),
    };
    let end_stage = start_stage
        .checked_add(stages - 1)
        .filter(|&end| end <= log_size)
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)?;
    let min_stride = pow2(start_stage - 1)?;
    let symbol = match (log_values, duplicate) {
        (2, false) => "b2n_noinit_block_batch<2,false>",
        (2, true) => "b2n_noinit_block_batch<2,true>",
        (3, false) => "b2n_noinit_block_batch<3,false>",
        (3, true) => "b2n_noinit_block_batch<3,true>",
        (4, false) => "b2n_noinit_block_batch<4,false>",
        (4, true) => "b2n_noinit_block_batch<4,true>",
        _ => return Err(BaseCommitAuthorityError::InvalidExecutionManifest),
    };
    Ok(kernel_3d(
        symbol,
        [min_stride / 32, pow2(log_size)? / pow2(end_stage)?, columns],
        [32, pow2(log_values)?, 1],
        b2n_interval_arguments(
            1,
            1,
            log_size,
            column_base,
            columns,
            start_stage,
            end_stage,
            Some(rescale_factor(log_size)?),
        )?,
    ))
}

fn n2b_manifest(
    log_size: u32,
    columns: u32,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    if !(3..=30).contains(&log_size) || columns == 0 {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    let mut result = Vec::new();
    for (column_base, chunk) in column_chunks(columns) {
        if let Some(parts) = n2b_parts(log_size) {
            let first = parts[0];
            result.push(n2b_nofinal(log_size, column_base, chunk, 2, first - 1)?);
            let mut start = 1 + first;
            for &stages in &parts[1..parts.len() - 1] {
                result.push(n2b_nofinal(log_size, column_base, chunk, start, stages)?);
                start += stages;
            }
            result.push(n2b_final(
                log_size,
                column_base,
                chunk,
                start,
                parts[parts.len() - 1],
            )?);
        } else {
            let block = if log_size <= 9 {
                pow2(log_size - 1)?
            } else {
                256
            };
            let grid = if log_size <= 9 {
                1
            } else {
                pow2(log_size - 9)?
            };
            for stage in 2..=log_size {
                result.push(kernel_3d(
                    "ntt_n2b_stage_batch",
                    [grid, chunk, 1],
                    [block, 1, 1],
                    n2b_stage_arguments(log_size, column_base, stage)?,
                ));
            }
        }
    }
    Ok(result)
}

fn n2b_parts(log_size: u32) -> Option<&'static [u32]> {
    match log_size {
        13..=19 => Some(&N2B_13_19[(log_size - 13) as usize]),
        20..=27 => Some(&N2B_20_27[(log_size - 20) as usize]),
        28..=30 => Some(&N2B_28_30[(log_size - 28) as usize]),
        _ => None,
    }
}

fn n2b_nofinal(
    log_size: u32,
    column_base: u32,
    columns: u32,
    start_stage: u32,
    stages: u32,
) -> Result<BaseCommitExecutionStep, BaseCommitAuthorityError> {
    let (log_values, log_warps, symbol) = match stages {
        5 => (3, 2, "n2b_nofinal_block_batch<3,2>"),
        6 => (3, 3, "n2b_nofinal_block_batch<3,3>"),
        7 => (4, 3, "n2b_nofinal_block_batch<4,3>"),
        8 => (4, 4, "n2b_nofinal_block_batch<4,4>"),
        _ => return Err(BaseCommitAuthorityError::InvalidExecutionManifest),
    };
    let end_stage = start_stage
        .checked_add(stages - 1)
        .filter(|&end| end <= log_size)
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)?;
    let min_stride = pow2(log_size - end_stage)?;
    let stage_width = pow2(log_values + log_warps)?;
    Ok(kernel_3d(
        symbol,
        [
            min_stride / 32,
            pow2(log_size)? / (min_stride * stage_width),
            columns,
        ],
        [32, pow2(log_warps)?, 1],
        n2b_interval_arguments(log_size, column_base, columns, start_stage, Some(end_stage))?,
    ))
}

fn n2b_final(
    log_size: u32,
    column_base: u32,
    columns: u32,
    start_stage: u32,
    stages: u32,
) -> Result<BaseCommitExecutionStep, BaseCommitAuthorityError> {
    if start_stage + stages != log_size + 1 {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    let (symbol, grid, block) = match stages {
        7 | 8 => {
            let log_values = stages - 5;
            let warps = pow2(log_size - 5 - log_values)?;
            let block_y = warps.min(4);
            (
                if stages == 7 {
                    "n2b_final_warp_batch<2,true>"
                } else {
                    "n2b_final_warp_batch<3,true>"
                },
                [warps / block_y, columns, 1],
                [32, block_y, 1],
            )
        }
        10 | 11 => {
            let log_warps = stages - 8;
            (
                if stages == 10 {
                    "n2b_final_block_warp_batch<2,true>"
                } else {
                    "n2b_final_block_warp_batch<3,true>"
                },
                [pow2(log_size - 8 - log_warps)?, 1, columns],
                [32, pow2(log_warps)?, 1],
            )
        }
        _ => return Err(BaseCommitAuthorityError::InvalidExecutionManifest),
    };
    Ok(kernel_3d(
        symbol,
        grid,
        block,
        n2b_interval_arguments(log_size, column_base, columns, start_stage, None)?,
    ))
}

fn expand_manifest(
    from_log_size: u32,
    to_log_size: u32,
    bands: u32,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    if from_log_size == 0 || from_log_size >= to_log_size || to_log_size >= 31 {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    let expansion = pow2(to_log_size - from_log_size)?;
    let mut pair_end = pow2(from_log_size - 1)?;
    let mut result = vec![device_copy(
        wrapper_buffer(2, 0),
        wrapper_buffer(3, 0),
        2 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64,
    )];
    while pair_end > 1 {
        let pair_begin = pair_end.div_ceil(expansion);
        result.push(kernel(
            "progressive_expand_pair_band",
            blocks(pair_end - pair_begin)?,
            BLOCK_SIZE,
            expand_arguments(
                pair_begin,
                pair_begin,
                pair_end - pair_begin,
                expansion,
                wrapper_buffer(2, 0),
                wrapper_buffer(2, 0),
            ),
        ));
        pair_end = pair_begin;
    }
    result.push(kernel(
        "progressive_expand_pair_band",
        1,
        BLOCK_SIZE,
        expand_arguments(
            0,
            0,
            1,
            expansion,
            wrapper_buffer(3, 0),
            wrapper_buffer(2, 0),
        ),
    ));
    exact_kernel_count(&result, bands)?;
    Ok(result)
}

fn finalize_manifest(
    log_size: u32,
    absorbed_columns: u32,
    bands: u32,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    let size = pow2(log_size)?;
    let mut result = vec![device_copy(
        wrapper_buffer(2, 0),
        wrapper_buffer(3, 0),
        PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64,
    )];
    let mut first = 1;
    while first < size {
        let end = size.min(
            first
                .checked_mul(3)
                .ok_or(BaseCommitAuthorityError::SizeOverflow)?,
        );
        result.push(kernel(
            "progressive_leaf_finalize_in_gpu",
            blocks(end - first)?,
            BLOCK_SIZE,
            finalize_arguments(
                end - first,
                absorbed_columns,
                wrapper_buffer(2, state_byte_offset(first)),
                wrapper_buffer(2, hash_byte_offset(first)),
            ),
        ));
        first = end;
    }
    result.push(kernel(
        "progressive_leaf_finalize_in_gpu",
        1,
        BLOCK_SIZE,
        finalize_arguments(
            1,
            absorbed_columns,
            wrapper_buffer(3, 0),
            wrapper_buffer(2, 0),
        ),
    ));
    exact_kernel_count(&result, bands)?;
    Ok(result)
}

fn merkle_in_place_manifest(
    output_hashes: u32,
    bands: u32,
) -> Result<Vec<BaseCommitExecutionStep>, BaseCommitAuthorityError> {
    if !output_hashes.is_power_of_two() {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    let mut result = vec![device_copy(
        wrapper_buffer(1, 0),
        wrapper_buffer(2, 0),
        (2 * core::mem::size_of::<Blake2sHash>()) as u64,
    )];
    let mut first = 1;
    while first < output_hashes {
        let end = output_hashes.min(
            first
                .checked_mul(2)
                .ok_or(BaseCommitAuthorityError::SizeOverflow)?,
        );
        result.push(kernel(
            "stwo_gpu_lab_blake2s_layer",
            blocks(end - first)?,
            BLOCK_SIZE,
            merkle_arguments(
                end - first,
                wrapper_buffer(1, hash_byte_offset(2 * first)),
                wrapper_buffer(1, hash_byte_offset(first)),
            ),
        ));
        first = end;
    }
    result.push(kernel(
        "stwo_gpu_lab_blake2s_layer",
        1,
        BLOCK_SIZE,
        merkle_arguments(1, wrapper_buffer(2, 0), wrapper_buffer(1, 0)),
    ));
    exact_kernel_count(&result, bands)?;
    Ok(result)
}

fn exact_kernel_count(
    steps: &[BaseCommitExecutionStep],
    expected: u32,
) -> Result<(), BaseCommitAuthorityError> {
    let actual = steps
        .iter()
        .filter(|step| matches!(step, BaseCommitExecutionStep::KernelLaunch(_)))
        .count();
    (u32::try_from(actual).ok() == Some(expected))
        .then_some(())
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)
}

fn validate_manifest(steps: &[BaseCommitExecutionStep]) -> Result<(), BaseCommitAuthorityError> {
    if steps.is_empty() {
        return Err(BaseCommitAuthorityError::InvalidExecutionManifest);
    }
    for step in steps {
        match step {
            BaseCommitExecutionStep::KernelLaunch(launch)
                if launch.symbol.is_empty()
                    || launch.grid.contains(&0)
                    || launch.block.contains(&0)
                    || launch.cluster.is_some_and(|cluster| cluster.contains(&0))
                    || launch.arguments.is_empty()
                    || launch
                        .arguments
                        .iter()
                        .any(|argument| argument.name.is_empty()) =>
            {
                return Err(BaseCommitAuthorityError::InvalidExecutionManifest)
            }
            BaseCommitExecutionStep::DeviceCopyD2D {
                source,
                destination,
                bytes,
            } if *bytes == 0 || source == destination => {
                return Err(BaseCommitAuthorityError::InvalidExecutionManifest)
            }
            _ => {}
        }
    }
    Ok(())
}

fn column_chunks(columns: u32) -> impl Iterator<Item = (u32, u32)> {
    (0..columns)
        .step_by(MAX_NTT_BATCH_COLUMNS as usize)
        .map(move |base| (base, (columns - base).min(MAX_NTT_BATCH_COLUMNS)))
}

fn count(value: usize) -> Result<u32, BaseCommitAuthorityError> {
    u32::try_from(value).map_err(|_| BaseCommitAuthorityError::SizeOverflow)
}

fn pow2(log_size: u32) -> Result<u32, BaseCommitAuthorityError> {
    1u32.checked_shl(log_size)
        .ok_or(BaseCommitAuthorityError::SizeOverflow)
}

fn blocks(size: u32) -> Result<u32, BaseCommitAuthorityError> {
    (size != 0)
        .then(|| size.div_ceil(BLOCK_SIZE))
        .ok_or(BaseCommitAuthorityError::InvalidExecutionManifest)
}
