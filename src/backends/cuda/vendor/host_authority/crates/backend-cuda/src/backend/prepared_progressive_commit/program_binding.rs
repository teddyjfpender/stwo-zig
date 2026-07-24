//! Fail-closed binding between an address-free [`CommitProgram`] and the
//! concrete prepared launch vector.

use super::*;
use crate::backend::commit_graph::CommitLaunchKind;
use crate::backend::progressive_commit::PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;
use crate::backend::progressive_commit_in_place::{
    expansion_band_plan, finalize_band_plan, merkle_band_plan, InPlaceBandPlan, InPlacePlanError,
    PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
};

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const HASH_BYTES: u64 = core::mem::size_of::<Blake2sHash>() as u64;
const MAX_NTT_BATCH_COLUMNS: u64 = 65_535;

/// Address-free projection of the actual prepared launch vector. Batch and
/// segment coordinates resolve exact canonical column membership through the
/// immutable program requirements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedCommitProgramView {
    pub storage: ProgressiveCommitStorageMode,
    pub leaf_launches: Vec<ProgressiveLeafLaunchKind>,
    pub merkle_launches: Vec<CommitLaunchKind>,
    pub retained_evaluation_words: Vec<Option<usize>>,
    pub retained_layer_words_bottom_up: Vec<usize>,
    pub root_is_last_retained_layer: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitProgramBindingError {
    Prepared(PreparedProgressiveCommitError),
    Program(CommitProgramError),
    StorageMode {
        expected: ProgressiveCommitStorageMode,
        actual: ProgressiveCommitStorageMode,
    },
    UnsupportedPreparedLaunch,
    StepCount {
        expected: usize,
        actual: usize,
    },
    StepOperation {
        index: usize,
        expected: CommitProgramOperation,
        actual: CommitProgramOperation,
    },
    StepTraffic {
        index: usize,
        expected: CommitProgramTraffic,
        actual: CommitProgramTraffic,
    },
    RetainedEvaluationCount {
        expected: usize,
        actual: usize,
    },
    RetainedEvaluation {
        canonical_column: usize,
        expected_words: Option<usize>,
        actual_words: Option<usize>,
    },
    RetainedLayerCount {
        expected: usize,
        actual: usize,
    },
    RetainedLayer {
        index: usize,
        expected_words: usize,
        actual_words: usize,
    },
    RootDestination,
    SizeOverflow,
}

impl core::fmt::Display for CommitProgramBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "prepared CUDA commitment disagrees with program: {self:?}"
        )
    }
}

impl std::error::Error for CommitProgramBindingError {}

impl From<PreparedProgressiveCommitError> for CommitProgramBindingError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Prepared(value)
    }
}

impl From<CommitProgramError> for CommitProgramBindingError {
    fn from(value: CommitProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<InPlacePlanError> for CommitProgramBindingError {
    fn from(value: InPlacePlanError) -> Self {
        Self::Program(CommitProgramError::InPlace(value))
    }
}

impl PreparedProgressiveCommitGraph<'_> {
    pub fn program_view(&self) -> PreparedCommitProgramView {
        let retained = self.retained_layers_bottom_up();
        let root = self.root_slice();
        PreparedCommitProgramView {
            storage: self.leaves.storage_mode(),
            leaf_launches: self.leaf_launch_sequence().collect(),
            merkle_launches: self.merkle_launch_sequence().collect(),
            retained_evaluation_words: self
                .retained_evaluations()
                .iter()
                .map(|output| output.map(ArenaSlice::len_words))
                .collect(),
            retained_layer_words_bottom_up: retained
                .iter()
                .map(|layer| layer.len_words())
                .collect(),
            root_is_last_retained_layer: retained.last().is_some_and(|last| {
                last.id() == root.id() && last.as_u32_ptr() == root.as_u32_ptr()
            }),
        }
    }
}

impl CommitProgram {
    /// Bind all concrete addresses through the already-qualified constructor,
    /// then reject the result unless its address-free projection is identical
    /// to this immutable program.
    pub fn bind<'a>(
        &self,
        arena: &'a DeviceArena,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<PreparedProgressiveCommitGraph<'a>, CommitProgramBindingError> {
        let identity = self.identity();
        let prepared =
            PreparedProgressiveCommitGraph::prepare_in_place_slab_with_modes_and_ntt_fusion(
                arena,
                identity.config,
                self.requirements(),
                slots,
                coefficients,
                retained_outputs,
                twiddles,
                ProgressiveCommitMode::DomainProgressive,
                identity.interior4_fused,
                identity.ntt_leaf_fusion,
            )?;
        self.validate_prepared(&prepared)?;
        Ok(prepared)
    }

    pub fn validate_prepared(
        &self,
        prepared: &PreparedProgressiveCommitGraph<'_>,
    ) -> Result<(), CommitProgramBindingError> {
        self.validate_prepared_view(&prepared.program_view())
    }

    pub fn validate_prepared_view(
        &self,
        actual: &PreparedCommitProgramView,
    ) -> Result<(), CommitProgramBindingError> {
        let expected_storage = self.identity().storage;
        if actual.storage != expected_storage {
            return Err(CommitProgramBindingError::StorageMode {
                expected: expected_storage,
                actual: actual.storage,
            });
        }

        let actual_steps = prepared_steps(self, actual)?;
        if actual_steps.len() != self.steps().len() {
            return Err(CommitProgramBindingError::StepCount {
                expected: self.steps().len(),
                actual: actual_steps.len(),
            });
        }
        for (index, (expected, actual)) in self.steps().iter().zip(&actual_steps).enumerate() {
            if expected.operation != actual.operation {
                return Err(CommitProgramBindingError::StepOperation {
                    index,
                    expected: expected.operation,
                    actual: actual.operation,
                });
            }
            if expected.traffic != actual.traffic {
                return Err(CommitProgramBindingError::StepTraffic {
                    index,
                    expected: expected.traffic,
                    actual: actual.traffic,
                });
            }
        }

        let columns = &self.requirements().leaves.plan.columns;
        if actual.retained_evaluation_words.len() != columns.len() {
            return Err(CommitProgramBindingError::RetainedEvaluationCount {
                expected: columns.len(),
                actual: actual.retained_evaluation_words.len(),
            });
        }
        for (canonical_column, (column, &actual_words)) in columns
            .iter()
            .zip(&actual.retained_evaluation_words)
            .enumerate()
        {
            let expected_words = column
                .retained_evaluation
                .then(|| words(column.evaluation_log_size))
                .transpose()?;
            if actual_words != expected_words {
                return Err(CommitProgramBindingError::RetainedEvaluation {
                    canonical_column,
                    expected_words,
                    actual_words,
                });
            }
        }

        let expected_layers = self.retained_layers_bottom_up();
        if actual.retained_layer_words_bottom_up.len() != expected_layers.len() {
            return Err(CommitProgramBindingError::RetainedLayerCount {
                expected: expected_layers.len(),
                actual: actual.retained_layer_words_bottom_up.len(),
            });
        }
        for (index, (expected, &actual_words)) in expected_layers
            .iter()
            .zip(&actual.retained_layer_words_bottom_up)
            .enumerate()
        {
            if expected.words != actual_words {
                return Err(CommitProgramBindingError::RetainedLayer {
                    index,
                    expected_words: expected.words,
                    actual_words,
                });
            }
        }
        if !actual.root_is_last_retained_layer {
            return Err(CommitProgramBindingError::RootDestination);
        }
        Ok(())
    }
}

fn prepared_steps(
    program: &CommitProgram,
    actual: &PreparedCommitProgramView,
) -> Result<Vec<CommitProgramStep>, CommitProgramBindingError> {
    let mut operations =
        Vec::with_capacity(actual.leaf_launches.len() + actual.merkle_launches.len());
    let mut absorbed_columns = 0u32;
    for &launch in &actual.leaf_launches {
        let operation = match launch {
            ProgressiveLeafLaunchKind::Init { log_size } => {
                CommitProgramOperation::StateInit { log_size }
            }
            ProgressiveLeafLaunchKind::ExpandInPlace {
                from_log_size,
                to_log_size,
            } => CommitProgramOperation::StateExpandInPlace {
                from_log_size,
                to_log_size,
                absorbed_columns,
                bands: band_count(&expansion_band_plan(
                    from_log_size,
                    to_log_size,
                    program.identity().geometry.lifting_log_size,
                )?)?,
            },
            ProgressiveLeafLaunchKind::Lde {
                batch_index,
                segment_offset,
                columns,
                log_size,
            } => CommitProgramOperation::Lde {
                batch_index,
                segment_offset,
                columns,
                log_size,
            },
            ProgressiveLeafLaunchKind::Absorb {
                batch_index,
                segment_offset,
                columns,
                log_size,
                absorbed_columns_before,
            } => {
                absorbed_columns = absorbed_columns_before
                    .checked_add(columns)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?;
                CommitProgramOperation::Absorb {
                    batch_index,
                    segment_offset,
                    columns,
                    log_size,
                    absorbed_columns_before,
                }
            }
            ProgressiveLeafLaunchKind::FusedLdeAbsorb {
                batch_index,
                segment_offset,
                columns,
                log_size,
                absorbed_columns_before,
                retained_write_mask,
            } => {
                if columns != 16 {
                    return Err(CommitProgramBindingError::UnsupportedPreparedLaunch);
                }
                absorbed_columns = absorbed_columns_before
                    .checked_add(columns)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?;
                CommitProgramOperation::FusedLdeAbsorb16 {
                    batch_index,
                    segment_offset,
                    log_size,
                    absorbed_columns_before,
                    retained_write_mask,
                }
            }
            ProgressiveLeafLaunchKind::FinalizeInPlace {
                log_size,
                absorbed_columns,
            } => CommitProgramOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                bands: band_count(&finalize_band_plan(words(log_size)?)?)?,
            },
            ProgressiveLeafLaunchKind::Expand { .. }
            | ProgressiveLeafLaunchKind::Finalize { .. }
            | ProgressiveLeafLaunchKind::DomainAbsorb { .. } => {
                return Err(CommitProgramBindingError::UnsupportedPreparedLaunch)
            }
        };
        operations.push(operation);
    }
    for &launch in &actual.merkle_launches {
        operations.push(match launch {
            CommitLaunchKind::InteriorLayerInPlace {
                level,
                output_hashes,
            } => CommitProgramOperation::MerkleLayerInPlace {
                level,
                output_hashes,
                bands: band_count(&merkle_band_plan(
                    output_hashes as usize,
                    slab_main_bytes(program)?,
                )?)?,
            },
            CommitLaunchKind::InteriorLayer {
                level,
                output_hashes,
            } => CommitProgramOperation::MerkleLayer {
                level,
                output_hashes,
            },
            CommitLaunchKind::FusedInterior4 {
                first_level,
                output_hashes,
            } => CommitProgramOperation::MerkleInterior4 {
                first_level,
                output_hashes,
            },
            CommitLaunchKind::FusedTail {
                first_hashes,
                levels,
            } => CommitProgramOperation::MerkleTail {
                first_hashes,
                levels,
            },
            _ => return Err(CommitProgramBindingError::UnsupportedPreparedLaunch),
        });
    }
    operations
        .into_iter()
        .map(|operation| {
            Ok(CommitProgramStep {
                operation,
                traffic: operation_traffic(program, operation)?,
            })
        })
        .collect()
}

fn operation_traffic(
    program: &CommitProgram,
    operation: CommitProgramOperation,
) -> Result<CommitProgramTraffic, CommitProgramBindingError> {
    let traffic = match operation {
        CommitProgramOperation::StateInit { log_size } => traffic(0, state_bytes(log_size)?, 1, 0),
        CommitProgramOperation::StateExpandInPlace {
            from_log_size,
            to_log_size,
            ..
        } => band_traffic(&expansion_band_plan(
            from_log_size,
            to_log_size,
            program.identity().geometry.lifting_log_size,
        )?)?,
        CommitProgramOperation::Lde {
            columns, log_size, ..
        } => {
            let evaluation = evaluation_bytes(log_size, columns)?;
            let ntt = ntt_launches(log_size)?;
            traffic(
                evaluation
                    .checked_mul(u64::from(ntt))
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                evaluation
                    .checked_mul(u64::from(ntt) + 1)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                lde_launches(log_size, columns)?,
                0,
            )
        }
        CommitProgramOperation::Absorb {
            columns, log_size, ..
        } => {
            let states = state_bytes(log_size)?;
            traffic(
                states
                    .checked_add(evaluation_bytes(log_size, columns)?)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                states,
                1,
                0,
            )
        }
        CommitProgramOperation::FusedLdeAbsorb16 {
            log_size,
            retained_write_mask,
            ..
        } => {
            let states = state_bytes(log_size)?;
            let evaluation = evaluation_bytes(log_size, 16)?;
            let ntt = ntt_launches(log_size)?;
            let evaluation_traffic = evaluation
                .checked_mul(u64::from(ntt))
                .ok_or(CommitProgramBindingError::SizeOverflow)?;
            let retained = evaluation_bytes(log_size, retained_write_mask.count_ones())?;
            traffic(
                states
                    .checked_add(evaluation_traffic)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                states
                    .checked_add(evaluation_traffic)
                    .and_then(|bytes| bytes.checked_add(retained))
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                ntt.checked_add(1)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?,
                0,
            )
        }
        CommitProgramOperation::FinalizeInPlace { log_size, .. } => {
            band_traffic(&finalize_band_plan(words(log_size)?)?)?
        }
        CommitProgramOperation::MerkleLayerInPlace { output_hashes, .. } => band_traffic(
            &merkle_band_plan(output_hashes as usize, slab_main_bytes(program)?)?,
        )?,
        CommitProgramOperation::MerkleLayer { output_hashes, .. } => traffic(
            u64::from(output_hashes) * 2 * HASH_BYTES,
            u64::from(output_hashes) * HASH_BYTES,
            1,
            0,
        ),
        CommitProgramOperation::MerkleInterior4 { output_hashes, .. } => traffic(
            u64::from(output_hashes) * 16 * HASH_BYTES,
            u64::from(output_hashes) * HASH_BYTES,
            1,
            0,
        ),
        CommitProgramOperation::MerkleTail {
            first_hashes,
            levels,
        } => {
            let mut hashes = u64::from(first_hashes);
            let mut read = 0u64;
            let mut write = 0u64;
            for _ in 0..levels {
                read = read
                    .checked_add(hashes * HASH_BYTES)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?;
                hashes /= 2;
                write = write
                    .checked_add(hashes * HASH_BYTES)
                    .ok_or(CommitProgramBindingError::SizeOverflow)?;
            }
            traffic(read, write, 1, 0)
        }
    };
    Ok(traffic)
}

fn band_traffic(plan: &InPlaceBandPlan) -> Result<CommitProgramTraffic, CommitProgramBindingError> {
    let read = plan
        .bands
        .iter()
        .try_fold(plan.save.0.len() as u64, |sum, band| {
            sum.checked_add(band.read.len() as u64)
                .ok_or(CommitProgramBindingError::SizeOverflow)
        })?;
    let write = plan
        .bands
        .iter()
        .try_fold(plan.save.1.len() as u64, |sum, band| {
            sum.checked_add(band.write.len() as u64)
                .ok_or(CommitProgramBindingError::SizeOverflow)
        })?;
    Ok(traffic(read, write, band_count(plan)?, 1))
}

fn band_count(plan: &InPlaceBandPlan) -> Result<u32, CommitProgramBindingError> {
    u32::try_from(plan.bands.len()).map_err(|_| CommitProgramBindingError::SizeOverflow)
}

fn traffic(
    read: u64,
    write: u64,
    kernel_launches: u32,
    device_copies: u32,
) -> CommitProgramTraffic {
    CommitProgramTraffic {
        owned_read_bytes: read,
        owned_write_bytes: write,
        kernel_launches,
        device_copies,
    }
}

fn words(log_size: u32) -> Result<usize, CommitProgramBindingError> {
    1usize
        .checked_shl(log_size)
        .ok_or(CommitProgramBindingError::SizeOverflow)
}

fn state_bytes(log_size: u32) -> Result<u64, CommitProgramBindingError> {
    u64::try_from(words(log_size)?)
        .ok()
        .and_then(|rows| rows.checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64))
        .ok_or(CommitProgramBindingError::SizeOverflow)
}

fn evaluation_bytes(log_size: u32, columns: u32) -> Result<u64, CommitProgramBindingError> {
    u64::try_from(words(log_size)?)
        .ok()
        .and_then(|rows| rows.checked_mul(u64::from(columns)))
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(CommitProgramBindingError::SizeOverflow)
}

fn ntt_launches(log_size: u32) -> Result<u32, CommitProgramBindingError> {
    match log_size {
        1..=12 => Ok(log_size),
        13..=19 => Ok(2),
        20..=27 => Ok(3),
        28..=30 => Ok(4),
        _ => Err(CommitProgramBindingError::SizeOverflow),
    }
}

fn lde_launches(log_size: u32, columns: u32) -> Result<u32, CommitProgramBindingError> {
    let chunks = (u64::from(columns) + MAX_NTT_BATCH_COLUMNS - 1) / MAX_NTT_BATCH_COLUMNS;
    u32::try_from(chunks)
        .ok()
        .and_then(|chunks| chunks.checked_mul(ntt_launches(log_size).ok()?.checked_add(1)?))
        .ok_or(CommitProgramBindingError::SizeOverflow)
}

fn slab_main_bytes(program: &CommitProgram) -> Result<usize, CommitProgramBindingError> {
    program
        .in_place_slab_words()?
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .and_then(|words| words.checked_mul(core::mem::size_of::<u32>()))
        .ok_or(CommitProgramBindingError::SizeOverflow)
}

#[cfg(test)]
#[path = "program_binding_tests.rs"]
mod tests;
