//! Address-free Mode-A program for retained, domain-progressive leaves.
//!
//! Every LDE is completed in its retained destination first. One standalone
//! cooperative Blake pass then consumes each canonical native-domain batch.
//! Expansion and finalization deliberately reuse the qualified in-place
//! program; only the per-16-column state round trips are replaced.

use super::*;
use crate::backend::progressive_commit::PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const STATE_WORDS: usize = PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES / core::mem::size_of::<u32>();
const MAX_NTT_BATCH_COLUMNS: u64 = 65_535;
const CACHE_TAG: &[u8] = b"stwo-domain-cooperative-commit-mode-a-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainCooperativeSlabSlice {
    pub offset_words: usize,
    pub len_words: usize,
}

impl DomainCooperativeSlabSlice {
    pub fn end_words(self) -> Option<usize> {
        self.offset_words.checked_add(self.len_words)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainCooperativeOperation {
    /// Full N2B LDE into the already-retained output. This is intentionally
    /// separate from Blake in Mode A and charges the later evaluation reread.
    LdeBatch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        log_size: u32,
    },
    /// One progressive-state-aware cooperative pass. `pending_*_words` uses
    /// BLAKE2s lazy-final-block semantics: a full pending block is 16, not 0.
    AbsorbDomainBatch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        log_size: u32,
        absorbed_columns_before: u32,
        pending_before_words: u32,
        pending_after_words: u32,
        initializes_state: bool,
        state: DomainCooperativeSlabSlice,
        leaf_compressions: u64,
    },
    StateExpandInPlace {
        from_log_size: u32,
        to_log_size: u32,
        absorbed_columns: u32,
        bands: u32,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        bands: u32,
        leaf_compressions: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainCooperativeStep {
    pub operation: DomainCooperativeOperation,
    pub traffic: CommitProgramTraffic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainCooperativeResourceModel {
    /// Four lanes distribute two chaining words and four pending words each.
    pub threads_per_row: u32,
    pub rows_per_block: u32,
    pub threads_per_block: u32,
    /// Native `__launch_bounds__` contract for the progressive quad kernel.
    pub launch_bounds_min_blocks_per_sm: u32,
    pub persistent_state_words_per_thread: u32,
    /// The existing spill-free quad is the reference, not a claim about the
    /// new kernel. Native admission must still enforce this ptxas ceiling.
    pub register_ceiling_per_thread: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainCooperativeComparison {
    /// Exact current ReplacementV1/Fused16 pre-Merkle traffic.
    pub current_leaf_traffic: CommitProgramTraffic,
    /// Exact Mode-A pre-Merkle traffic, including retained evaluation rereads.
    pub replacement_leaf_traffic: CommitProgramTraffic,
    /// Every retained evaluation byte read by Mode A after the completed LDE.
    pub retained_evaluation_reread_bytes: u64,
    /// Bytes already reread by non-fused remainder absorbs in the current
    /// program. These cannot be credited to the replacement a second time.
    pub current_retained_evaluation_reread_bytes: u64,
    /// The exact additional HBM read charged against current Fused16.
    pub incremental_retained_evaluation_reread_bytes: u64,
    pub current_state_api_calls: u32,
    pub replacement_state_api_calls: u32,
    pub current_leaf_compressions: u64,
    pub replacement_leaf_compressions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainCooperativeProgram {
    cache_key: u64,
    steps: Vec<DomainCooperativeStep>,
    merkle_suffix: Vec<CommitProgramStep>,
    slab_words: usize,
    resource_model: DomainCooperativeResourceModel,
    comparison: DomainCooperativeComparison,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainCooperativeProgramError {
    Base(CommitProgramError),
    WrongStorage(ProgressiveCommitStorageMode),
    RequiresRetainedEvaluations { canonical_column: usize },
    MissingBaseOperation,
    InvalidMerkleSuffix,
    CompressionMismatch { expected: u64, actual: u64 },
    NonCanonicalProgram,
    SizeOverflow,
}

impl core::fmt::Display for DomainCooperativeProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid domain-cooperative CUDA commitment program: {self:?}"
        )
    }
}

impl std::error::Error for DomainCooperativeProgramError {}

impl From<CommitProgramError> for DomainCooperativeProgramError {
    fn from(value: CommitProgramError) -> Self {
        Self::Base(value)
    }
}

impl DomainCooperativeProgram {
    /// Compile the default-off, retained-only Mode-A replacement. No selector
    /// or native launch is enabled merely by constructing this pure program.
    pub fn compile_mode_a(base: &CommitProgram) -> Result<Self, DomainCooperativeProgramError> {
        let program = Self::compile_canonical(base)?;
        program.validate_against(base)?;
        Ok(program)
    }

    pub fn validate_against(
        &self,
        base: &CommitProgram,
    ) -> Result<(), DomainCooperativeProgramError> {
        if *self == Self::compile_canonical(base)? {
            Ok(())
        } else {
            Err(DomainCooperativeProgramError::NonCanonicalProgram)
        }
    }

    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub fn steps(&self) -> &[DomainCooperativeStep] {
        &self.steps
    }

    pub fn merkle_suffix(&self) -> &[CommitProgramStep] {
        &self.merkle_suffix
    }

    pub fn slab_words(&self) -> usize {
        self.slab_words
    }

    pub fn resource_model(&self) -> DomainCooperativeResourceModel {
        self.resource_model
    }

    pub fn comparison(&self) -> DomainCooperativeComparison {
        self.comparison
    }

    pub fn canonical_columns_for_step(&self, step: usize) -> Option<core::ops::Range<usize>> {
        let (first, columns) = match self.steps.get(step)?.operation {
            DomainCooperativeOperation::LdeBatch {
                first_column,
                columns,
                ..
            }
            | DomainCooperativeOperation::AbsorbDomainBatch {
                first_column,
                columns,
                ..
            } => (first_column as usize, columns as usize),
            _ => return None,
        };
        Some(first..first.checked_add(columns)?)
    }

    fn compile_canonical(base: &CommitProgram) -> Result<Self, DomainCooperativeProgramError> {
        if base.identity().storage != ProgressiveCommitStorageMode::InPlaceSlab {
            return Err(DomainCooperativeProgramError::WrongStorage(
                base.identity().storage,
            ));
        }
        let plan = &base.requirements().leaves.plan;
        if let Some(column) = plan
            .columns
            .iter()
            .find(|column| !column.retained_evaluation)
        {
            return Err(DomainCooperativeProgramError::RequiresRetainedEvaluations {
                canonical_column: column.canonical_index,
            });
        }

        let mut steps = Vec::with_capacity(plan.lde_batches.len() * 2 + 8);
        let mut replacement_traffic = CommitProgramTraffic::default();
        for (batch_index, batch) in plan.lde_batches.iter().enumerate() {
            let traffic = full_lde_traffic(batch)?;
            replacement_traffic = add_traffic(replacement_traffic, traffic)?;
            steps.push(DomainCooperativeStep {
                operation: DomainCooperativeOperation::LdeBatch {
                    batch_index: as_u32(batch_index)?,
                    first_column: as_u32(
                        *batch
                            .columns
                            .first()
                            .ok_or(DomainCooperativeProgramError::MissingBaseOperation)?,
                    )?,
                    columns: as_u32(batch.columns.len())?,
                    log_size: batch.evaluation_log_size,
                },
                traffic,
            });
        }

        let mut current_log = plan.columns[0].evaluation_log_size;
        let mut replacement_compressions = 0u64;
        for (batch_index, batch) in plan.lde_batches.iter().enumerate() {
            let first = *batch
                .columns
                .first()
                .ok_or(DomainCooperativeProgramError::MissingBaseOperation)?;
            if batch.evaluation_log_size > current_log {
                let expansion = base_expansion(base, current_log, batch.evaluation_log_size)?;
                replacement_traffic = add_traffic(replacement_traffic, expansion.traffic)?;
                steps.push(expansion);
                current_log = batch.evaluation_log_size;
            }
            let end = first
                .checked_add(batch.columns.len())
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
            let compressions = u64::try_from(block_boundaries(first, end))
                .ok()
                .and_then(|count| count.checked_mul(rows_u64(batch.evaluation_log_size).ok()?))
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
            replacement_compressions = replacement_compressions
                .checked_add(compressions)
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
            let state_bytes = rows_u64(batch.evaluation_log_size)?
                .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64)
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
            let evaluation_bytes = u64::try_from(batch.output_words)
                .ok()
                .and_then(|words| words.checked_mul(WORD_BYTES))
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
            let initializes_state = batch_index == 0;
            let traffic = CommitProgramTraffic {
                owned_read_bytes: evaluation_bytes
                    .checked_add(if initializes_state { 0 } else { state_bytes })
                    .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
                owned_write_bytes: state_bytes,
                kernel_launches: 1,
                device_copies: 0,
            };
            replacement_traffic = add_traffic(replacement_traffic, traffic)?;
            steps.push(DomainCooperativeStep {
                operation: DomainCooperativeOperation::AbsorbDomainBatch {
                    batch_index: as_u32(batch_index)?,
                    first_column: as_u32(first)?,
                    columns: as_u32(batch.columns.len())?,
                    log_size: batch.evaluation_log_size,
                    absorbed_columns_before: as_u32(first)?,
                    pending_before_words: as_u32(pending_words(first))?,
                    pending_after_words: as_u32(pending_words(end))?,
                    initializes_state,
                    state: DomainCooperativeSlabSlice {
                        offset_words: 0,
                        len_words: rows_usize(batch.evaluation_log_size)?
                            .checked_mul(STATE_WORDS)
                            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
                    },
                    leaf_compressions: compressions,
                },
                traffic,
            });
        }

        let lifting = plan.geometry.lifting_log_size;
        if current_log < lifting {
            let expansion = base_expansion(base, current_log, lifting)?;
            replacement_traffic = add_traffic(replacement_traffic, expansion.traffic)?;
            steps.push(expansion);
        }
        let finalize = base_finalize(base)?;
        let final_compressions = rows_u64(lifting)?;
        replacement_compressions = replacement_compressions
            .checked_add(final_compressions)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
        replacement_traffic = add_traffic(replacement_traffic, finalize.traffic)?;
        steps.push(DomainCooperativeStep {
            operation: match finalize.operation {
                DomainCooperativeOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    bands,
                    ..
                } => DomainCooperativeOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    bands,
                    leaf_compressions: final_compressions,
                },
                _ => return Err(DomainCooperativeProgramError::MissingBaseOperation),
            },
            traffic: finalize.traffic,
        });

        let expected_compressions = u64::try_from(plan.accounting.progressive_leaf_compressions)
            .map_err(|_| DomainCooperativeProgramError::SizeOverflow)?;
        if replacement_compressions != expected_compressions {
            return Err(DomainCooperativeProgramError::CompressionMismatch {
                expected: expected_compressions,
                actual: replacement_compressions,
            });
        }
        let (merkle_suffix, _) = merkle_suffix(base)?;
        let comparison = comparison(
            base,
            &steps,
            replacement_traffic,
            expected_compressions,
            plan.accounting.lde_output_words,
        )?;
        Ok(Self {
            cache_key: cache_key(base.identity().cache_key),
            steps,
            merkle_suffix,
            slab_words: base.in_place_slab_words()?,
            resource_model: DomainCooperativeResourceModel {
                threads_per_row: 4,
                rows_per_block: 64,
                threads_per_block: 256,
                launch_bounds_min_blocks_per_sm: 5,
                persistent_state_words_per_thread: 6,
                register_ceiling_per_thread: 48,
            },
            comparison,
        })
    }
}

fn full_lde_traffic(
    batch: &crate::backend::progressive_commit::SameLogLdeBatch,
) -> Result<CommitProgramTraffic, DomainCooperativeProgramError> {
    let bytes = u64::try_from(batch.output_words)
        .ok()
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
    let ntt = ntt_launches(batch.evaluation_log_size)?;
    Ok(CommitProgramTraffic {
        owned_read_bytes: bytes
            .checked_mul(u64::from(ntt))
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
        owned_write_bytes: bytes
            .checked_mul(u64::from(ntt) + 1)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
        kernel_launches: lde_launches(batch.evaluation_log_size, batch.columns.len())?,
        device_copies: 0,
    })
}

fn base_expansion(
    base: &CommitProgram,
    from: u32,
    to: u32,
) -> Result<DomainCooperativeStep, DomainCooperativeProgramError> {
    base.steps()
        .iter()
        .find_map(|step| match step.operation {
            CommitProgramOperation::StateExpandInPlace {
                from_log_size,
                to_log_size,
                absorbed_columns,
                bands,
            } if from_log_size == from && to_log_size == to => Some(DomainCooperativeStep {
                operation: DomainCooperativeOperation::StateExpandInPlace {
                    from_log_size,
                    to_log_size,
                    absorbed_columns,
                    bands,
                },
                traffic: step.traffic,
            }),
            _ => None,
        })
        .ok_or(DomainCooperativeProgramError::MissingBaseOperation)
}

fn base_finalize(
    base: &CommitProgram,
) -> Result<DomainCooperativeStep, DomainCooperativeProgramError> {
    base.steps()
        .iter()
        .find_map(|step| match step.operation {
            CommitProgramOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                bands,
            } => Some(DomainCooperativeStep {
                operation: DomainCooperativeOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    bands,
                    leaf_compressions: 0,
                },
                traffic: step.traffic,
            }),
            _ => None,
        })
        .ok_or(DomainCooperativeProgramError::MissingBaseOperation)
}

fn comparison(
    base: &CommitProgram,
    steps: &[DomainCooperativeStep],
    replacement_leaf_traffic: CommitProgramTraffic,
    compressions: u64,
    lde_output_words: usize,
) -> Result<DomainCooperativeComparison, DomainCooperativeProgramError> {
    let mut current_leaf_traffic = CommitProgramTraffic::default();
    let mut current_state_api_calls = 0u32;
    let mut current_retained_evaluation_reread_bytes = 0u64;
    for step in base
        .steps()
        .iter()
        .filter(|step| !is_merkle(step.operation))
    {
        current_leaf_traffic = add_traffic(current_leaf_traffic, step.traffic)?;
        if let CommitProgramOperation::Absorb {
            columns, log_size, ..
        } = step.operation
        {
            current_retained_evaluation_reread_bytes = current_retained_evaluation_reread_bytes
                .checked_add(
                    rows_u64(log_size)?
                        .checked_mul(u64::from(columns))
                        .and_then(|words| words.checked_mul(WORD_BYTES))
                        .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
                )
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
        }
        if !matches!(step.operation, CommitProgramOperation::Lde { .. }) {
            current_state_api_calls = current_state_api_calls
                .checked_add(1)
                .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
        }
    }
    let replacement_state_api_calls = as_u32(
        steps
            .iter()
            .filter(|step| !matches!(step.operation, DomainCooperativeOperation::LdeBatch { .. }))
            .count(),
    )?;
    let retained_evaluation_reread_bytes = u64::try_from(lde_output_words)
        .ok()
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
    let incremental_retained_evaluation_reread_bytes = retained_evaluation_reread_bytes
        .checked_sub(current_retained_evaluation_reread_bytes)
        .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
    Ok(DomainCooperativeComparison {
        current_leaf_traffic,
        replacement_leaf_traffic,
        retained_evaluation_reread_bytes,
        current_retained_evaluation_reread_bytes,
        incremental_retained_evaluation_reread_bytes,
        current_state_api_calls,
        replacement_state_api_calls,
        current_leaf_compressions: compressions,
        replacement_leaf_compressions: compressions,
    })
}

fn merkle_suffix(
    base: &CommitProgram,
) -> Result<(Vec<CommitProgramStep>, CommitProgramTraffic), DomainCooperativeProgramError> {
    let mut saw_finalize = false;
    let mut suffix = Vec::new();
    let mut traffic = CommitProgramTraffic::default();
    for &step in base.steps() {
        match step.operation {
            CommitProgramOperation::FinalizeInPlace { .. } => saw_finalize = true,
            operation if is_merkle(operation) => {
                if !saw_finalize {
                    return Err(DomainCooperativeProgramError::InvalidMerkleSuffix);
                }
                traffic = add_traffic(traffic, step.traffic)?;
                suffix.push(step);
            }
            _ if !suffix.is_empty() => {
                return Err(DomainCooperativeProgramError::InvalidMerkleSuffix)
            }
            _ => {}
        }
    }
    if !saw_finalize || suffix.is_empty() {
        return Err(DomainCooperativeProgramError::InvalidMerkleSuffix);
    }
    Ok((suffix, traffic))
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

fn pending_words(absorbed_columns: usize) -> usize {
    if absorbed_columns == 0 {
        0
    } else {
        (absorbed_columns - 1) % 16 + 1
    }
}

fn block_boundaries(first: usize, end: usize) -> usize {
    if first >= end {
        return 0;
    }
    (end - 1) / 16 - first.saturating_sub(1) / 16
}

fn ntt_launches(log_size: u32) -> Result<u32, DomainCooperativeProgramError> {
    match log_size {
        1..=12 => Ok(log_size),
        13..=19 => Ok(2),
        20..=27 => Ok(3),
        28..=30 => Ok(4),
        _ => Err(DomainCooperativeProgramError::SizeOverflow),
    }
}

fn lde_launches(log_size: u32, columns: usize) -> Result<u32, DomainCooperativeProgramError> {
    let launches_per_chunk = ntt_launches(log_size)?
        .checked_add(1)
        .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
    let chunks = u64::try_from(columns)
        .ok()
        .and_then(|count| count.checked_add(MAX_NTT_BATCH_COLUMNS - 1))
        .map(|count| count / MAX_NTT_BATCH_COLUMNS)
        .ok_or(DomainCooperativeProgramError::SizeOverflow)?;
    u32::try_from(chunks)
        .ok()
        .and_then(|chunks| chunks.checked_mul(launches_per_chunk))
        .ok_or(DomainCooperativeProgramError::SizeOverflow)
}

fn add_traffic(
    left: CommitProgramTraffic,
    right: CommitProgramTraffic,
) -> Result<CommitProgramTraffic, DomainCooperativeProgramError> {
    Ok(CommitProgramTraffic {
        owned_read_bytes: left
            .owned_read_bytes
            .checked_add(right.owned_read_bytes)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
        owned_write_bytes: left
            .owned_write_bytes
            .checked_add(right.owned_write_bytes)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
        kernel_launches: left
            .kernel_launches
            .checked_add(right.kernel_launches)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
        device_copies: left
            .device_copies
            .checked_add(right.device_copies)
            .ok_or(DomainCooperativeProgramError::SizeOverflow)?,
    })
}

fn rows_u64(log_size: u32) -> Result<u64, DomainCooperativeProgramError> {
    1u64.checked_shl(log_size)
        .ok_or(DomainCooperativeProgramError::SizeOverflow)
}

fn rows_usize(log_size: u32) -> Result<usize, DomainCooperativeProgramError> {
    1usize
        .checked_shl(log_size)
        .ok_or(DomainCooperativeProgramError::SizeOverflow)
}

fn as_u32(value: usize) -> Result<u32, DomainCooperativeProgramError> {
    u32::try_from(value).map_err(|_| DomainCooperativeProgramError::SizeOverflow)
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
#[path = "domain_cooperative_tests.rs"]
mod tests;
