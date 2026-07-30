//! Pure ReplacementV1 program for a staged, shape-wide commitment leaf pass.
//!
//! One tree is live at a time. Native-domain LDE outputs occupy the space
//! released by the 96-byte progressive states, then one combined descriptor
//! table presents every column in canonical order to the cooperative quad
//! leaf kernel. The ordinary prepared Merkle suffix is retained verbatim.

use core::ops::Range;

use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / core::mem::size_of::<u32>();
const HASH_BYTES: u64 = core::mem::size_of::<Blake2sHash>() as u64;
const MAX_NTT_BATCH_COLUMNS: u64 = 65_535;
const CACHE_TAG: &[u8] = b"stwo-shape-wide-commit-replacement-v1";

/// Native pointer/log record consumed by the shape-wide leaf kernels. The pad
/// is required and must be zero; sealing it keeps Rust/CUDA strides identical.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeWideColumnDescriptorAbi {
    pub column: *const u32,
    pub evaluation_log_size: u32,
    pub reserved: u32,
}

const _: () = assert!(core::mem::size_of::<ShapeWideColumnDescriptorAbi>() == 16);
const _: () = assert!(core::mem::align_of::<ShapeWideColumnDescriptorAbi>() == 8);
const COMBINED_DESCRIPTOR_WORDS: usize =
    core::mem::size_of::<ShapeWideColumnDescriptorAbi>() / core::mem::size_of::<u32>();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShapeWideColumnStorage {
    Staged { offset_words: usize },
    Retained { group: usize, column: usize },
}

/// Address-free entry in the one combined pointer/log table. The native ABI
/// is four words: one 64-bit pointer, one log-size word, and one pad word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeWideColumn {
    pub canonical_index: usize,
    pub evaluation_log_size: u32,
    pub words: usize,
    pub storage: ShapeWideColumnStorage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShapeWideLeafOperation {
    StageLdeBatch {
        batch_index: u32,
        first_column: u32,
        log_size: u32,
        columns: u32,
    },
    /// Initializes the 32-byte hash state in registers and consumes every
    /// non-final 16-column block in one cooperative launch.
    QuadUpdate { columns: u32 },
    /// Consumes the exact final width (1..=16), sets the BLAKE2s final flag,
    /// and writes the canonical leaf layer. If no full prefix exists this
    /// launch initializes the state itself.
    RemainderFinalize {
        first_column: u32,
        columns: u32,
        initializes_state: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeWideLeafStep {
    pub operation: ShapeWideLeafOperation,
    pub traffic: CommitProgramTraffic,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShapeWideSlabLayout {
    pub available_words: usize,
    pub required_words: usize,
    pub leaf_hashes: Range<usize>,
    pub staged_evaluations: Range<usize>,
    /// The existing one-slab scratch stays at its qualified fixed tail. Any
    /// gap before it is deliberately unused and available to later tuning.
    pub scratch: Range<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShapeWideCommitComparison {
    /// Complete pre-Merkle program traffic. Both sides include their NTT
    /// passes, so this model claims no NTT saving and cannot double-credit one.
    pub current_leaf_traffic: CommitProgramTraffic,
    pub replacement_leaf_traffic: CommitProgramTraffic,
    /// Algorithmic state transitions only. Final leaf-output writes are
    /// excluded from both sides. This is a byte credit, not a wall-time claim.
    pub current_state_transition_bytes: u64,
    pub replacement_state_transition_bytes: u64,
    pub state_transition_bytes_eliminated: u64,
    pub current_state_api_calls: u32,
    pub replacement_state_api_calls: u32,
    pub current_leaf_compressions: u64,
    pub replacement_leaf_compressions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShapeWideCommitProgram {
    cache_key: u64,
    columns: Vec<ShapeWideColumn>,
    leaf_steps: Vec<ShapeWideLeafStep>,
    merkle_suffix: Vec<CommitProgramStep>,
    slab: ShapeWideSlabLayout,
    materialized_evaluation_words: usize,
    retained_evaluation_words: usize,
    combined_descriptor_words: usize,
    tree_working_words: usize,
    traffic: CommitProgramTraffic,
    comparison: ShapeWideCommitComparison,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ShapeWideCommitProgramError {
    Base(CommitProgramError),
    WrongStorage(ProgressiveCommitStorageMode),
    MissingFinalize,
    InvalidMerkleSuffix,
    StagingExceedsSlab { required: usize, available: usize },
    SizeOverflow,
}

impl core::fmt::Display for ShapeWideCommitProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid shape-wide CUDA commitment program: {self:?}")
    }
}

impl std::error::Error for ShapeWideCommitProgramError {}

impl From<CommitProgramError> for ShapeWideCommitProgramError {
    fn from(value: CommitProgramError) -> Self {
        Self::Base(value)
    }
}

impl ShapeWideCommitProgram {
    /// Compile the dormant ReplacementV1 lane. The method name is intentional:
    /// legacy/default dispatch has no ambient switch into this architecture.
    pub fn compile_replacement_v1(
        base: &CommitProgram,
    ) -> Result<Self, ShapeWideCommitProgramError> {
        if base.identity().storage != ProgressiveCommitStorageMode::InPlaceSlab {
            return Err(ShapeWideCommitProgramError::WrongStorage(
                base.identity().storage,
            ));
        }
        let plan = &base.requirements().leaves.plan;
        let rows = words(plan.geometry.lifting_log_size)?;
        let leaf_hash_words = rows
            .checked_mul(HASH_WORDS)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        let available_words = base.in_place_slab_words()?;
        let slab_main_words = available_words
            .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;

        let mut staging_words = 0usize;
        let mut retained_evaluation_words = 0usize;
        let mut materialized_evaluation_words = 0usize;
        let mut columns = Vec::with_capacity(plan.columns.len());
        for column in &plan.columns {
            let column_words = words(column.evaluation_log_size)?;
            materialized_evaluation_words = materialized_evaluation_words
                .checked_add(column_words)
                .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
            let storage = if column.retained_evaluation {
                retained_evaluation_words = retained_evaluation_words
                    .checked_add(column_words)
                    .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
                ShapeWideColumnStorage::Retained {
                    group: column.group_index,
                    column: column.column_in_group,
                }
            } else {
                let offset_words = leaf_hash_words
                    .checked_add(staging_words)
                    .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
                staging_words = staging_words
                    .checked_add(column_words)
                    .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
                ShapeWideColumnStorage::Staged { offset_words }
            };
            columns.push(ShapeWideColumn {
                canonical_index: column.canonical_index,
                evaluation_log_size: column.evaluation_log_size,
                words: column_words,
                storage,
            });
        }
        let staging_end = leaf_hash_words
            .checked_add(staging_words)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        if staging_end > slab_main_words {
            return Err(ShapeWideCommitProgramError::StagingExceedsSlab {
                required: staging_end + PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
                available: available_words,
            });
        }
        let required_words = staging_end
            .checked_add(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        let slab = ShapeWideSlabLayout {
            available_words,
            required_words,
            leaf_hashes: 0..leaf_hash_words,
            staged_evaluations: leaf_hash_words..staging_end,
            scratch: slab_main_words..available_words,
        };

        let (leaf_steps, replacement_leaf_traffic) = leaf_steps(plan, rows)?;
        let (merkle_suffix, merkle_traffic) = merkle_suffix(base)?;
        let traffic = add_traffic(replacement_leaf_traffic, merkle_traffic)?;
        let combined_descriptor_words = columns
            .len()
            .checked_mul(COMBINED_DESCRIPTOR_WORDS)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        let tree_working_words = materialized_evaluation_words
            .checked_add(leaf_hash_words)
            .and_then(|value| value.checked_add(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS))
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        let comparison = comparison(base, &leaf_steps, replacement_leaf_traffic, rows)?;

        Ok(Self {
            cache_key: cache_key(base.identity().cache_key),
            columns,
            leaf_steps,
            merkle_suffix,
            slab,
            materialized_evaluation_words,
            retained_evaluation_words,
            combined_descriptor_words,
            tree_working_words,
            traffic,
            comparison,
        })
    }

    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub fn columns(&self) -> &[ShapeWideColumn] {
        &self.columns
    }

    pub fn leaf_steps(&self) -> &[ShapeWideLeafStep] {
        &self.leaf_steps
    }

    /// Exact canonical descriptor slice consumed by one staged LDE API call.
    pub fn columns_for_leaf_step(&self, step: usize) -> Option<&[ShapeWideColumn]> {
        let ShapeWideLeafOperation::StageLdeBatch {
            first_column,
            columns,
            ..
        } = self.leaf_steps.get(step)?.operation
        else {
            return None;
        };
        let begin = first_column as usize;
        self.columns
            .get(begin..begin.checked_add(columns as usize)?)
    }

    pub fn merkle_suffix(&self) -> &[CommitProgramStep] {
        &self.merkle_suffix
    }

    pub fn slab(&self) -> &ShapeWideSlabLayout {
        &self.slab
    }

    /// Native-domain words materialized for the whole tree, including outputs
    /// already retained elsewhere for decommitment or quotient consumers.
    pub fn materialized_evaluation_words(&self) -> usize {
        self.materialized_evaluation_words
    }

    /// Words that must actually occupy the replaced one-slab allocation.
    pub fn staged_evaluation_words(&self) -> usize {
        self.slab.staged_evaluations.len()
    }

    pub fn retained_evaluation_words(&self) -> usize {
        self.retained_evaluation_words
    }

    pub fn combined_descriptor_words(&self) -> usize {
        self.combined_descriptor_words
    }

    /// Conservative simultaneous tree footprint: every materialized native
    /// evaluation plus the 32-byte lifting-domain leaf layer and scratch.
    pub fn tree_working_words(&self) -> usize {
        self.tree_working_words
    }

    pub fn traffic(&self) -> CommitProgramTraffic {
        self.traffic
    }

    pub fn comparison(&self) -> ShapeWideCommitComparison {
        self.comparison
    }
}

fn leaf_steps(
    plan: &ProgressiveCommitPlan,
    rows: usize,
) -> Result<(Vec<ShapeWideLeafStep>, CommitProgramTraffic), ShapeWideCommitProgramError> {
    let mut steps = Vec::with_capacity(plan.lde_batches.len() + 2);
    let mut total = CommitProgramTraffic::default();
    for (batch_index, batch) in plan.lde_batches.iter().enumerate() {
        let columns = u32::try_from(batch.columns.len())
            .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?;
        let ntt = ntt_launches(batch.evaluation_log_size)?;
        let evaluation_bytes = u64::try_from(batch.output_words)
            .ok()
            .and_then(|value| value.checked_mul(WORD_BYTES))
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        let traffic = CommitProgramTraffic {
            owned_read_bytes: evaluation_bytes
                .checked_mul(u64::from(ntt))
                .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
            owned_write_bytes: evaluation_bytes
                .checked_mul(u64::from(ntt) + 1)
                .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
            kernel_launches: lde_launches(batch.evaluation_log_size, columns)?,
            device_copies: 0,
        };
        total = add_traffic(total, traffic)?;
        steps.push(ShapeWideLeafStep {
            operation: ShapeWideLeafOperation::StageLdeBatch {
                batch_index: u32::try_from(batch_index)
                    .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?,
                first_column: u32::try_from(
                    *batch
                        .columns
                        .first()
                        .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
                )
                .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?,
                log_size: batch.evaluation_log_size,
                columns,
            },
            traffic,
        });
    }

    let column_count =
        u32::try_from(plan.columns.len()).map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?;
    let final_columns = ((column_count - 1) % 16) + 1;
    let update_columns = column_count - final_columns;
    let row_bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(HASH_BYTES))
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
    if update_columns != 0 {
        let traffic = CommitProgramTraffic {
            owned_read_bytes: evaluation_read_bytes(rows, update_columns)?,
            owned_write_bytes: row_bytes,
            kernel_launches: 1,
            device_copies: 0,
        };
        total = add_traffic(total, traffic)?;
        steps.push(ShapeWideLeafStep {
            operation: ShapeWideLeafOperation::QuadUpdate {
                columns: update_columns,
            },
            traffic,
        });
    }
    let finalize_traffic = CommitProgramTraffic {
        owned_read_bytes: evaluation_read_bytes(rows, final_columns)?
            .checked_add(if update_columns == 0 { 0 } else { row_bytes })
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
        owned_write_bytes: row_bytes,
        kernel_launches: 1,
        device_copies: 0,
    };
    total = add_traffic(total, finalize_traffic)?;
    steps.push(ShapeWideLeafStep {
        operation: ShapeWideLeafOperation::RemainderFinalize {
            first_column: update_columns,
            columns: final_columns,
            initializes_state: update_columns == 0,
        },
        traffic: finalize_traffic,
    });
    Ok((steps, total))
}

fn merkle_suffix(
    base: &CommitProgram,
) -> Result<(Vec<CommitProgramStep>, CommitProgramTraffic), ShapeWideCommitProgramError> {
    let mut saw_finalize = false;
    let mut suffix = Vec::new();
    let mut traffic = CommitProgramTraffic::default();
    for &step in base.steps() {
        match step.operation {
            CommitProgramOperation::FinalizeInPlace { .. } => saw_finalize = true,
            operation if is_merkle(operation) => {
                if !saw_finalize {
                    return Err(ShapeWideCommitProgramError::InvalidMerkleSuffix);
                }
                traffic = add_traffic(traffic, step.traffic)?;
                suffix.push(step);
            }
            _ if !suffix.is_empty() => {
                return Err(ShapeWideCommitProgramError::InvalidMerkleSuffix)
            }
            _ => {}
        }
    }
    if !saw_finalize {
        return Err(ShapeWideCommitProgramError::MissingFinalize);
    }
    if suffix.is_empty() {
        return Err(ShapeWideCommitProgramError::InvalidMerkleSuffix);
    }
    Ok((suffix, traffic))
}

fn comparison(
    base: &CommitProgram,
    replacement_steps: &[ShapeWideLeafStep],
    replacement_leaf_traffic: CommitProgramTraffic,
    rows: usize,
) -> Result<ShapeWideCommitComparison, ShapeWideCommitProgramError> {
    let mut current_leaf_traffic = CommitProgramTraffic::default();
    let mut current_state_api_calls = 0u32;
    for step in base.steps() {
        if is_merkle(step.operation) {
            continue;
        }
        current_leaf_traffic = add_traffic(current_leaf_traffic, step.traffic)?;
        if !matches!(step.operation, CommitProgramOperation::Lde { .. }) {
            current_state_api_calls = current_state_api_calls
                .checked_add(1)
                .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
        }
    }
    let replacement_state_api_calls = u32::try_from(
        replacement_steps
            .iter()
            .filter(|step| !matches!(step.operation, ShapeWideLeafOperation::StageLdeBatch { .. }))
            .count(),
    )
    .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?;
    let has_update = replacement_steps
        .iter()
        .any(|step| matches!(step.operation, ShapeWideLeafOperation::QuadUpdate { .. }));
    let row_hash_bytes = u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(HASH_BYTES))
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
    let replacement_state_transition_bytes = if has_update {
        row_hash_bytes
            .checked_mul(2)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?
    } else {
        0
    };
    let current_state_transition_bytes = u64::try_from(
        base.requirements()
            .leaves
            .plan
            .accounting
            .state_total_traffic_bytes,
    )
    .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?;
    let state_transition_bytes_eliminated = current_state_transition_bytes
        .checked_sub(replacement_state_transition_bytes)
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
    let accounting = &base.requirements().leaves.plan.accounting;
    Ok(ShapeWideCommitComparison {
        current_leaf_traffic,
        replacement_leaf_traffic,
        current_state_transition_bytes,
        replacement_state_transition_bytes,
        state_transition_bytes_eliminated,
        current_state_api_calls,
        replacement_state_api_calls,
        current_leaf_compressions: u64::try_from(accounting.progressive_leaf_compressions)
            .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?,
        replacement_leaf_compressions: u64::try_from(accounting.full_lifting_leaf_compressions)
            .map_err(|_| ShapeWideCommitProgramError::SizeOverflow)?,
    })
}

fn is_merkle(operation: CommitProgramOperation) -> bool {
    matches!(
        operation,
        CommitProgramOperation::MerkleLayerInPlace { .. }
            | CommitProgramOperation::MerkleLayer { .. }
            | CommitProgramOperation::MerkleInterior4 { .. }
            | CommitProgramOperation::MerkleTail { .. }
    )
}

fn evaluation_read_bytes(rows: usize, columns: u32) -> Result<u64, ShapeWideCommitProgramError> {
    u64::try_from(rows)
        .ok()
        .and_then(|value| value.checked_mul(u64::from(columns)))
        .and_then(|value| value.checked_mul(WORD_BYTES))
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)
}

fn words(log_size: u32) -> Result<usize, ShapeWideCommitProgramError> {
    1usize
        .checked_shl(log_size)
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)
}

fn ntt_launches(log_size: u32) -> Result<u32, ShapeWideCommitProgramError> {
    match log_size {
        1..=12 => Ok(log_size),
        13..=19 => Ok(2),
        20..=27 => Ok(3),
        28..=30 => Ok(4),
        _ => Err(ShapeWideCommitProgramError::SizeOverflow),
    }
}

fn lde_launches(log_size: u32, columns: u32) -> Result<u32, ShapeWideCommitProgramError> {
    let per_chunk = ntt_launches(log_size)?
        .checked_add(1)
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)?;
    let chunks = (u64::from(columns) + MAX_NTT_BATCH_COLUMNS - 1) / MAX_NTT_BATCH_COLUMNS;
    u32::try_from(chunks)
        .ok()
        .and_then(|value| value.checked_mul(per_chunk))
        .ok_or(ShapeWideCommitProgramError::SizeOverflow)
}

fn add_traffic(
    left: CommitProgramTraffic,
    right: CommitProgramTraffic,
) -> Result<CommitProgramTraffic, ShapeWideCommitProgramError> {
    Ok(CommitProgramTraffic {
        owned_read_bytes: left
            .owned_read_bytes
            .checked_add(right.owned_read_bytes)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
        owned_write_bytes: left
            .owned_write_bytes
            .checked_add(right.owned_write_bytes)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
        kernel_launches: left
            .kernel_launches
            .checked_add(right.kernel_launches)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
        device_copies: left
            .device_copies
            .checked_add(right.device_copies)
            .ok_or(ShapeWideCommitProgramError::SizeOverflow)?,
    })
}

fn cache_key(base: u64) -> u64 {
    CACHE_TAG
        .iter()
        .chain(base.to_le_bytes().iter())
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

#[cfg(test)]
#[path = "shape_wide_tests.rs"]
mod tests;
