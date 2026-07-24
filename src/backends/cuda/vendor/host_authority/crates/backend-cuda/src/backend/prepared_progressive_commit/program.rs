//! Address-free executable manifest for the one-slab commitment program.
//!
//! This is the immutable bridge between Cairo topology admission and CUDA
//! preparation. It records every prepared API call, the exact nested
//! kernel/copy counts, owned-buffer traffic, retained-layer order, and an
//! independent CPU fixture oracle. It contains no device address and no
//! Cairo-specific policy.

use stwo::core::vcs::blake2_hash::Blake2sHash;

use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitError, ProgressiveCommitGeometry, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
};
use crate::backend::progressive_commit_in_place::{
    expansion_band_plan, finalize_band_plan, merkle_band_plan, InPlaceBandPlan, InPlacePlanError,
    PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
};
use crate::backend::progressive_ntt_leaf_fusion::{
    progressive_lde_segments, ProgressiveLdeSegmentKind,
};

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const HASH_BYTES: u64 = core::mem::size_of::<Blake2sHash>() as u64;
// Mirrors the CUDA grid-y limit enforced by `lde_n2b_columns_on`. Keep this
// explicit here: the manifest is an admission boundary, not telemetry sampled
// from an already-prepared launch list.
const MAX_NTT_BATCH_COLUMNS: u64 = 65_535;
const PROGRAM_CACHE_TAG: &[u8] = b"stwo-commit-program-in-place-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProgramIdentity {
    pub config: CommitWorkspaceConfig,
    pub geometry: ProgressiveCommitGeometry,
    pub storage: ProgressiveCommitStorageMode,
    pub ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
    pub interior4_fused: bool,
    pub cache_key: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitProgramOperation {
    StateInit {
        log_size: u32,
    },
    StateExpandInPlace {
        from_log_size: u32,
        to_log_size: u32,
        absorbed_columns: u32,
        bands: u32,
    },
    Lde {
        batch_index: u32,
        segment_offset: u32,
        columns: u32,
        log_size: u32,
    },
    Absorb {
        batch_index: u32,
        segment_offset: u32,
        columns: u32,
        log_size: u32,
        absorbed_columns_before: u32,
    },
    FusedLdeAbsorb16 {
        batch_index: u32,
        segment_offset: u32,
        log_size: u32,
        absorbed_columns_before: u32,
        retained_write_mask: u32,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        bands: u32,
    },
    MerkleLayerInPlace {
        level: u32,
        output_hashes: u32,
        bands: u32,
    },
    MerkleLayer {
        level: u32,
        output_hashes: u32,
    },
    MerkleInterior4 {
        first_level: u32,
        output_hashes: u32,
    },
    MerkleTail {
        first_hashes: u32,
        levels: u32,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CommitProgramTraffic {
    /// Reads from commitment-owned state, materialized evaluation, or hash
    /// buffers. Coefficient and twiddle reads are deliberately excluded.
    pub owned_read_bytes: u64,
    pub owned_write_bytes: u64,
    pub kernel_launches: u32,
    pub device_copies: u32,
}

impl CommitProgramTraffic {
    pub fn total_owned_bytes(self) -> Result<u64, CommitProgramError> {
        self.owned_read_bytes
            .checked_add(self.owned_write_bytes)
            .ok_or(CommitProgramError::SizeOverflow)
    }

    fn checked_add(self, rhs: Self) -> Result<Self, CommitProgramError> {
        Ok(Self {
            owned_read_bytes: self
                .owned_read_bytes
                .checked_add(rhs.owned_read_bytes)
                .ok_or(CommitProgramError::SizeOverflow)?,
            owned_write_bytes: self
                .owned_write_bytes
                .checked_add(rhs.owned_write_bytes)
                .ok_or(CommitProgramError::SizeOverflow)?,
            kernel_launches: self
                .kernel_launches
                .checked_add(rhs.kernel_launches)
                .ok_or(CommitProgramError::SizeOverflow)?,
            device_copies: self
                .device_copies
                .checked_add(rhs.device_copies)
                .ok_or(CommitProgramError::SizeOverflow)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitProgramStep {
    pub operation: CommitProgramOperation,
    pub traffic: CommitProgramTraffic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommitProgramLayer {
    pub log_size: u32,
    pub words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitProgram {
    identity: CommitProgramIdentity,
    requirements: ProgressiveCommitWorkspaceRequirements,
    steps: Vec<CommitProgramStep>,
    traffic: CommitProgramTraffic,
    retained_layers_bottom_up: Vec<CommitProgramLayer>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitProgramError {
    Prepared(PreparedProgressiveCommitError),
    Progressive(ProgressiveCommitError),
    InPlace(InPlacePlanError),
    InvalidInPlaceConfiguration,
    InvalidRetainedLayerOrder,
    SizeOverflow,
}

impl core::fmt::Display for CommitProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid CUDA commitment program: {self:?}")
    }
}

impl std::error::Error for CommitProgramError {}

impl From<PreparedProgressiveCommitError> for CommitProgramError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Prepared(value)
    }
}

impl From<ProgressiveCommitError> for CommitProgramError {
    fn from(value: ProgressiveCommitError) -> Self {
        Self::Progressive(value)
    }
}

impl From<InPlacePlanError> for CommitProgramError {
    fn from(value: InPlacePlanError) -> Self {
        Self::InPlace(value)
    }
}

impl CommitProgram {
    /// Compile one immutable address-free program. The in-place lane requires
    /// at least one unretained bottom layer; no legacy fallback is selected.
    pub fn compile(
        config: CommitWorkspaceConfig,
        geometry: ProgressiveCommitGeometry,
        ntt_leaf_fusion: ProgressiveNttLeafFusionMode,
        interior4_fused: bool,
    ) -> Result<Self, CommitProgramError> {
        if config.unretained_bottom_layers == 0 {
            return Err(CommitProgramError::InvalidInPlaceConfiguration);
        }
        let requirements = progressive_commit_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            config,
            geometry.clone(),
        )?;
        let mut steps = leaf_steps(&requirements.leaves, ntt_leaf_fusion)?;
        steps.extend(merkle_steps(
            config,
            requirements.leaves.in_place_slab_words()?,
            interior4_fused,
        )?);
        let traffic = steps
            .iter()
            .try_fold(CommitProgramTraffic::default(), |total, step| {
                total.checked_add(step.traffic)
            })?;
        let retained_layers_bottom_up = requirements
            .merkle
            .retained_layers
            .iter()
            .chain(&requirements.merkle.tail_outputs)
            .map(|layer| CommitProgramLayer {
                log_size: layer.log_size,
                words: layer.words,
            })
            .collect::<Vec<_>>();
        if retained_layers_bottom_up.last().map(|layer| layer.log_size) != Some(0)
            || retained_layers_bottom_up
                .windows(2)
                .any(|pair| pair[0].log_size != pair[1].log_size + 1)
        {
            return Err(CommitProgramError::InvalidRetainedLayerOrder);
        }
        let identity = CommitProgramIdentity {
            cache_key: commit_program_cache_key(
                config,
                &geometry,
                ntt_leaf_fusion,
                interior4_fused,
            ),
            config,
            geometry,
            storage: ProgressiveCommitStorageMode::InPlaceSlab,
            ntt_leaf_fusion,
            interior4_fused,
        };
        Ok(Self {
            identity,
            requirements,
            steps,
            traffic,
            retained_layers_bottom_up,
        })
    }

    pub fn identity(&self) -> &CommitProgramIdentity {
        &self.identity
    }

    pub fn requirements(&self) -> &ProgressiveCommitWorkspaceRequirements {
        &self.requirements
    }

    pub fn steps(&self) -> &[CommitProgramStep] {
        &self.steps
    }

    /// Exact canonical plan membership for an LDE/absorb API call. The pair
    /// `(batch_index, segment_offset)` is sealed into each operation, so no
    /// contiguous numeric column assumption is required.
    pub fn canonical_columns_for_step(&self, step: usize) -> Option<&[usize]> {
        let (batch, offset, columns) = match self.steps.get(step)?.operation {
            CommitProgramOperation::Lde {
                batch_index,
                segment_offset,
                columns,
                ..
            }
            | CommitProgramOperation::Absorb {
                batch_index,
                segment_offset,
                columns,
                ..
            } => (batch_index, segment_offset, columns),
            CommitProgramOperation::FusedLdeAbsorb16 {
                batch_index,
                segment_offset,
                ..
            } => (batch_index, segment_offset, 16),
            _ => return None,
        };
        let batch = self
            .requirements
            .leaves
            .plan
            .lde_batches
            .get(batch as usize)?;
        let begin = offset as usize;
        batch
            .columns
            .get(begin..begin.checked_add(columns as usize)?)
    }

    pub fn traffic(&self) -> CommitProgramTraffic {
        self.traffic
    }

    pub fn retained_layers_bottom_up(&self) -> &[CommitProgramLayer] {
        &self.retained_layers_bottom_up
    }

    pub fn in_place_slab_words(&self) -> Result<usize, CommitProgramError> {
        Ok(self.requirements.leaves.in_place_slab_words()?)
    }
}

fn leaf_steps(
    requirements: &ProgressiveLeafWorkspaceRequirements,
    fusion: ProgressiveNttLeafFusionMode,
) -> Result<Vec<CommitProgramStep>, CommitProgramError> {
    let first_log = requirements.plan.columns[0].evaluation_log_size;
    let mut current_log = first_log;
    let mut absorbed_columns = 0u32;
    let mut steps = vec![step(
        CommitProgramOperation::StateInit {
            log_size: first_log,
        },
        0,
        state_bytes(first_log)?,
        1,
        0,
    )];
    for (batch_index, batch) in requirements.plan.lde_batches.iter().enumerate() {
        if batch.evaluation_log_size > current_log {
            steps.push(expansion_step(
                current_log,
                batch.evaluation_log_size,
                requirements.plan.geometry.lifting_log_size,
                absorbed_columns,
            )?);
            current_log = batch.evaluation_log_size;
        }
        let (segments, _) = progressive_lde_segments(batch, fusion)?;
        for segment in segments {
            let columns =
                u32::try_from(segment.columns).map_err(|_| CommitProgramError::SizeOverflow)?;
            let batch_index =
                u32::try_from(batch_index).map_err(|_| CommitProgramError::SizeOverflow)?;
            let segment_offset =
                u32::try_from(segment.offset).map_err(|_| CommitProgramError::SizeOverflow)?;
            let rows = rows(batch.evaluation_log_size)?;
            let evaluation_bytes = rows
                .checked_mul(u64::from(columns))
                .and_then(|words| words.checked_mul(WORD_BYTES))
                .ok_or(CommitProgramError::SizeOverflow)?;
            let states = state_bytes(batch.evaluation_log_size)?;
            match segment.kind {
                ProgressiveLdeSegmentKind::Separate => {
                    let ntt_kernels = n2b_kernel_launches(batch.evaluation_log_size)?;
                    let lde_kernels =
                        lde_kernel_launches(batch.evaluation_log_size, u64::from(columns))?;
                    steps.push(step(
                        CommitProgramOperation::Lde {
                            batch_index,
                            segment_offset,
                            columns,
                            log_size: batch.evaluation_log_size,
                        },
                        evaluation_bytes
                            .checked_mul(u64::from(ntt_kernels))
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        evaluation_bytes
                            .checked_mul(u64::from(ntt_kernels) + 1)
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        lde_kernels,
                        0,
                    ));
                    steps.push(step(
                        CommitProgramOperation::Absorb {
                            batch_index,
                            segment_offset,
                            columns,
                            log_size: batch.evaluation_log_size,
                            absorbed_columns_before: absorbed_columns,
                        },
                        states
                            .checked_add(evaluation_bytes)
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        states,
                        1,
                        0,
                    ));
                }
                ProgressiveLdeSegmentKind::Fused16 {
                    retained_write_mask,
                } => {
                    let ntt_kernels = n2b_kernel_launches(batch.evaluation_log_size)?;
                    let retained_bytes = rows
                        .checked_mul(u64::from(retained_write_mask.count_ones()))
                        .and_then(|words| words.checked_mul(WORD_BYTES))
                        .ok_or(CommitProgramError::SizeOverflow)?;
                    steps.push(step(
                        CommitProgramOperation::FusedLdeAbsorb16 {
                            batch_index,
                            segment_offset,
                            log_size: batch.evaluation_log_size,
                            absorbed_columns_before: absorbed_columns,
                            retained_write_mask,
                        },
                        states
                            .checked_add(
                                evaluation_bytes
                                    .checked_mul(u64::from(ntt_kernels))
                                    .ok_or(CommitProgramError::SizeOverflow)?,
                            )
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        states
                            .checked_add(
                                evaluation_bytes
                                    .checked_mul(u64::from(ntt_kernels))
                                    .ok_or(CommitProgramError::SizeOverflow)?,
                            )
                            .and_then(|bytes| bytes.checked_add(retained_bytes))
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        ntt_kernels
                            .checked_add(1)
                            .ok_or(CommitProgramError::SizeOverflow)?,
                        0,
                    ));
                }
            }
            absorbed_columns = absorbed_columns
                .checked_add(columns)
                .ok_or(CommitProgramError::SizeOverflow)?;
        }
    }
    let lifting = requirements.plan.geometry.lifting_log_size;
    if current_log < lifting {
        steps.push(expansion_step(
            current_log,
            lifting,
            lifting,
            absorbed_columns,
        )?);
    }
    let plan = finalize_band_plan(
        usize::try_from(rows(lifting)?).map_err(|_| CommitProgramError::SizeOverflow)?,
    )?;
    let traffic = band_traffic(&plan)?;
    steps.push(CommitProgramStep {
        operation: CommitProgramOperation::FinalizeInPlace {
            log_size: lifting,
            absorbed_columns,
            bands: u32::try_from(plan.bands.len()).map_err(|_| CommitProgramError::SizeOverflow)?,
        },
        traffic,
    });
    Ok(steps)
}

fn merkle_steps(
    config: CommitWorkspaceConfig,
    slab_words: usize,
    interior4_fused: bool,
) -> Result<Vec<CommitProgramStep>, CommitProgramError> {
    let tail_levels = config
        .max_fused_tail_levels
        .min(config.lifting_log_size - config.unretained_bottom_layers);
    let interior_levels = config.lifting_log_size - tail_levels;
    let slab_main_bytes = slab_words
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u32>()))
        .ok_or(CommitProgramError::SizeOverflow)?;
    let mut steps = Vec::new();
    let mut level = 0u32;
    while level < interior_levels {
        let output_log = config.lifting_log_size - level - 1;
        let output_hashes = 1u32
            .checked_shl(output_log)
            .ok_or(CommitProgramError::SizeOverflow)?;
        let legal_fused4 = interior4_fused
            && level + 4 <= interior_levels
            && level + 3 < config.unretained_bottom_layers
            && level + 4 >= config.unretained_bottom_layers;
        if legal_fused4 {
            let fused_output_hashes = output_hashes >> 3;
            steps.push(step(
                CommitProgramOperation::MerkleInterior4 {
                    first_level: level,
                    output_hashes: fused_output_hashes,
                },
                u64::from(fused_output_hashes)
                    .checked_mul(16 * HASH_BYTES)
                    .ok_or(CommitProgramError::SizeOverflow)?,
                u64::from(fused_output_hashes)
                    .checked_mul(HASH_BYTES)
                    .ok_or(CommitProgramError::SizeOverflow)?,
                1,
                0,
            ));
            level += 4;
            continue;
        }
        if level + 1 < config.unretained_bottom_layers {
            let plan = merkle_band_plan(output_hashes as usize, slab_main_bytes)?;
            steps.push(CommitProgramStep {
                operation: CommitProgramOperation::MerkleLayerInPlace {
                    level,
                    output_hashes,
                    bands: u32::try_from(plan.bands.len())
                        .map_err(|_| CommitProgramError::SizeOverflow)?,
                },
                traffic: band_traffic(&plan)?,
            });
        } else {
            steps.push(step(
                CommitProgramOperation::MerkleLayer {
                    level,
                    output_hashes,
                },
                u64::from(output_hashes)
                    .checked_mul(2 * HASH_BYTES)
                    .ok_or(CommitProgramError::SizeOverflow)?,
                u64::from(output_hashes)
                    .checked_mul(HASH_BYTES)
                    .ok_or(CommitProgramError::SizeOverflow)?,
                1,
                0,
            ));
        }
        level += 1;
    }
    if tail_levels != 0 {
        let first_hashes = 1u32
            .checked_shl(tail_levels)
            .ok_or(CommitProgramError::SizeOverflow)?;
        let mut hashes = u64::from(first_hashes);
        let mut read = 0u64;
        let mut write = 0u64;
        for _ in 0..tail_levels {
            read = read
                .checked_add(
                    hashes
                        .checked_mul(HASH_BYTES)
                        .ok_or(CommitProgramError::SizeOverflow)?,
                )
                .ok_or(CommitProgramError::SizeOverflow)?;
            hashes /= 2;
            write = write
                .checked_add(
                    hashes
                        .checked_mul(HASH_BYTES)
                        .ok_or(CommitProgramError::SizeOverflow)?,
                )
                .ok_or(CommitProgramError::SizeOverflow)?;
        }
        steps.push(step(
            CommitProgramOperation::MerkleTail {
                first_hashes,
                levels: tail_levels,
            },
            read,
            write,
            1,
            0,
        ));
    }
    Ok(steps)
}

fn expansion_step(
    from_log_size: u32,
    to_log_size: u32,
    capacity_log_size: u32,
    absorbed_columns: u32,
) -> Result<CommitProgramStep, CommitProgramError> {
    let plan = expansion_band_plan(from_log_size, to_log_size, capacity_log_size)?;
    Ok(CommitProgramStep {
        operation: CommitProgramOperation::StateExpandInPlace {
            from_log_size,
            to_log_size,
            absorbed_columns,
            bands: u32::try_from(plan.bands.len()).map_err(|_| CommitProgramError::SizeOverflow)?,
        },
        traffic: band_traffic(&plan)?,
    })
}

fn band_traffic(plan: &InPlaceBandPlan) -> Result<CommitProgramTraffic, CommitProgramError> {
    let read = plan
        .bands
        .iter()
        .try_fold(plan.save.0.len() as u64, |total, band| {
            total
                .checked_add(band.read.len() as u64)
                .ok_or(CommitProgramError::SizeOverflow)
        })?;
    let write = plan
        .bands
        .iter()
        .try_fold(plan.save.1.len() as u64, |total, band| {
            total
                .checked_add(band.write.len() as u64)
                .ok_or(CommitProgramError::SizeOverflow)
        })?;
    Ok(CommitProgramTraffic {
        owned_read_bytes: read,
        owned_write_bytes: write,
        kernel_launches: u32::try_from(plan.bands.len())
            .map_err(|_| CommitProgramError::SizeOverflow)?,
        device_copies: 1,
    })
}

fn step(
    operation: CommitProgramOperation,
    owned_read_bytes: u64,
    owned_write_bytes: u64,
    kernel_launches: u32,
    device_copies: u32,
) -> CommitProgramStep {
    CommitProgramStep {
        operation,
        traffic: CommitProgramTraffic {
            owned_read_bytes,
            owned_write_bytes,
            kernel_launches,
            device_copies,
        },
    }
}

fn state_bytes(log_size: u32) -> Result<u64, CommitProgramError> {
    rows(log_size)?
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64)
        .ok_or(CommitProgramError::SizeOverflow)
}

/// Exact number of in-place evaluation read/write NTT kernels selected by
/// `ntt_n2b_columns_dispatch_on`. The staging kernel is counted separately by
/// each LDE API-call step.
fn n2b_kernel_launches(log_size: u32) -> Result<u32, CommitProgramError> {
    match log_size {
        1..=12 => Ok(log_size),
        13..=19 => Ok(2),
        20..=27 => Ok(3),
        28..=30 => Ok(4),
        _ => Err(CommitProgramError::SizeOverflow),
    }
}

/// Exact stage-plus-NTT launches after `lde_n2b_columns_on` tiles grid-y.
fn lde_kernel_launches(log_size: u32, columns: u64) -> Result<u32, CommitProgramError> {
    let launches_per_chunk = n2b_kernel_launches(log_size)?
        .checked_add(1)
        .ok_or(CommitProgramError::SizeOverflow)?;
    let chunks = columns
        .checked_add(MAX_NTT_BATCH_COLUMNS - 1)
        .ok_or(CommitProgramError::SizeOverflow)?
        / MAX_NTT_BATCH_COLUMNS;
    u32::try_from(chunks)
        .map_err(|_| CommitProgramError::SizeOverflow)?
        .checked_mul(launches_per_chunk)
        .ok_or(CommitProgramError::SizeOverflow)
}

fn rows(log_size: u32) -> Result<u64, CommitProgramError> {
    1u64.checked_shl(log_size)
        .ok_or(CommitProgramError::SizeOverflow)
}

fn commit_program_cache_key(
    config: CommitWorkspaceConfig,
    geometry: &ProgressiveCommitGeometry,
    fusion: ProgressiveNttLeafFusionMode,
    interior4_fused: bool,
) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut feed = |bytes: &[u8]| {
        for &byte in bytes {
            hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
    };
    feed(PROGRAM_CACHE_TAG);
    feed(&config.log_blowup_factor.to_le_bytes());
    feed(&config.lifting_log_size.to_le_bytes());
    feed(&config.unretained_bottom_layers.to_le_bytes());
    feed(&config.max_fused_tail_levels.to_le_bytes());
    feed(&[match fusion {
        ProgressiveNttLeafFusionMode::Separate => 0,
        ProgressiveNttLeafFusionMode::Fused16 => 1,
    }]);
    feed(&[u8::from(interior4_fused)]);
    feed(&geometry.lifting_log_size.to_le_bytes());
    feed(&geometry.log_blowup_factor.to_le_bytes());
    feed(&(geometry.groups.len() as u64).to_le_bytes());
    for group in &geometry.groups {
        feed(&[u8::from(group.retain_evaluations)]);
        feed(&(group.coefficient_log_sizes.len() as u64).to_le_bytes());
        for log_size in &group.coefficient_log_sizes {
            feed(&log_size.to_le_bytes());
        }
    }
    hash
}

#[cfg(test)]
#[path = "program_tests.rs"]
mod tests;
