//! Pure mixed terminal/expand-absorb execution program.
//!
//! Materialized batches following a domain rise use the disjoint source-major
//! successor. Fixed16 batches keep their qualified terminal sink and perform
//! the preceding compact expansion in place. Two fixed h8 banks make those
//! choices composable while guaranteeing that final hashes land at slab zero.

use std::collections::BTreeSet;

use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectTerminalExpandAbsorbError {
    Fused(FusedCompactDomainProgramError),
    Terminal(DirectCompactTerminalError),
    ProgramIdentity,
    MissingBatch(u32),
    DuplicateBatch(u32),
    InvalidBatch(u32),
    InvalidState,
    MissingFinalize,
    SlabCapacity,
    SizeOverflow,
}

impl core::fmt::Display for DirectTerminalExpandAbsorbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid direct terminal expand-absorb program: {self:?}")
    }
}

impl std::error::Error for DirectTerminalExpandAbsorbError {}

impl From<FusedCompactDomainProgramError> for DirectTerminalExpandAbsorbError {
    fn from(value: FusedCompactDomainProgramError) -> Self {
        Self::Fused(value)
    }
}

impl From<DirectCompactTerminalError> for DirectTerminalExpandAbsorbError {
    fn from(value: DirectCompactTerminalError) -> Self {
        Self::Terminal(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectTerminalExpandAbsorbTransition {
    None {
        state: DomainCooperativeSlabSlice,
    },
    Materialized {
        from_log_size: u32,
        to_log_size: u32,
        expansion_bands: u32,
        source_state: DomainCooperativeSlabSlice,
        destination_state: DomainCooperativeSlabSlice,
        scratch: DomainCooperativeSlabSlice,
    },
    Fixed16InPlace {
        from_log_size: u32,
        to_log_size: u32,
        expansion_bands: u32,
        state: DomainCooperativeSlabSlice,
        scratch: DomainCooperativeSlabSlice,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectTerminalExpandAbsorbOperation {
    Batch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        log_size: u32,
        mode: DirectCompactTerminalBatchMode,
        initializes_state: bool,
        reconstructed_tail: Option<CompactDomainTail>,
        transition: DirectTerminalExpandAbsorbTransition,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        reconstructed_tail: CompactDomainTail,
        state: DomainCooperativeSlabSlice,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectTerminalExpandAbsorbReceipt {
    pub qualified_slab_capacity_words: usize,
    pub state_bank_words: usize,
    pub materialized_batches: u32,
    pub fixed16_batches: u32,
    pub fused_materialized_rises: u32,
    pub fixed16_rises: u32,
    pub kernel_launches_removed: u32,
    pub device_copies_removed: u32,
    pub expanded_state_write_bytes_removed: u64,
    pub expanded_state_reread_bytes_removed: u64,
    pub expansion_scratch_read_bytes_removed: u64,
    pub expansion_scratch_write_bytes_removed: u64,
    pub fixed16_terminal_receipt_unchanged: bool,
    pub final_state_at_slab_zero: bool,
    pub same_gpu_timing_credit_applied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectTerminalExpandAbsorbProgram {
    operations: Vec<DirectTerminalExpandAbsorbOperation>,
    receipt: DirectTerminalExpandAbsorbReceipt,
}

impl DirectTerminalExpandAbsorbProgram {
    pub fn compile(
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
        fused: &FusedCompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
        terminal: &DirectCompactTerminalProgram,
    ) -> Result<Self, DirectTerminalExpandAbsorbError> {
        fused.validate_against(base, domain, compact)?;
        if direct.commit_cache_key() != base.identity().cache_key {
            return Err(DirectTerminalExpandAbsorbError::ProgramIdentity);
        }
        terminal.validate_against(compact, direct)?;
        compile_canonical(fused, terminal)
    }

    pub fn validate_against(
        &self,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
        fused: &FusedCompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
        terminal: &DirectCompactTerminalProgram,
    ) -> Result<(), DirectTerminalExpandAbsorbError> {
        let expected = Self::compile(base, domain, compact, fused, direct, terminal)?;
        if *self == expected {
            Ok(())
        } else {
            Err(DirectTerminalExpandAbsorbError::ProgramIdentity)
        }
    }

    pub fn operations(&self) -> &[DirectTerminalExpandAbsorbOperation] {
        &self.operations
    }

    pub fn receipt(&self) -> &DirectTerminalExpandAbsorbReceipt {
        &self.receipt
    }
}

fn compile_canonical(
    fused: &FusedCompactDomainProgram,
    terminal: &DirectCompactTerminalProgram,
) -> Result<DirectTerminalExpandAbsorbProgram, DirectTerminalExpandAbsorbError> {
    let terminal_batches = &terminal.receipt().batches;
    let batch_mode = |batch_index: u32| {
        terminal_batches
            .get(batch_index as usize)
            .filter(|batch| batch.batch_index == batch_index)
            .ok_or(DirectTerminalExpandAbsorbError::MissingBatch(batch_index))
    };
    let fused_rises = fused
        .steps()
        .iter()
        .filter_map(|step| match step.operation {
            FusedCompactDomainOperation::ExpandAbsorbDomainBatch { batch_index, .. } => {
                Some(batch_index)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let materialized_rises = fused_rises
        .iter()
        .map(|&batch_index| batch_mode(batch_index))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|batch| matches!(batch.mode, DirectCompactTerminalBatchMode::Materialized))
        .count();
    let final_state_words = fused
        .steps()
        .iter()
        .find_map(|step| match step.operation {
            FusedCompactDomainOperation::FinalizeInPlace { state, .. } => Some(state.len_words),
            _ => None,
        })
        .ok_or(DirectTerminalExpandAbsorbError::MissingFinalize)?;
    let qualified_words = fused.receipt().qualified_slab_capacity_words;
    let scratch_offset = qualified_words
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(DirectTerminalExpandAbsorbError::SlabCapacity)?;
    if final_state_words
        .checked_mul(2)
        .filter(|&words| words <= scratch_offset)
        .is_none()
    {
        return Err(DirectTerminalExpandAbsorbError::SlabCapacity);
    }
    let scratch = DomainCooperativeSlabSlice {
        offset_words: scratch_offset,
        len_words: PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
    };
    let state = |bank: usize, log_size: u32| {
        let len_words = 1usize
            .checked_shl(log_size)
            .and_then(|rows| rows.checked_mul(HASH_WORDS))
            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
        if len_words > final_state_words || bank > 1 {
            return Err(DirectTerminalExpandAbsorbError::SlabCapacity);
        }
        Ok(DomainCooperativeSlabSlice {
            offset_words: bank
                .checked_mul(final_state_words)
                .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?,
            len_words,
        })
    };

    let mut bank = materialized_rises & 1;
    let mut operations = Vec::with_capacity(terminal_batches.len() + 1);
    let mut seen = BTreeSet::new();
    let mut fused_materialized_rises = 0u32;
    let mut fixed16_rises = 0u32;
    let mut kernel_launches_removed = 0u32;
    let mut device_copies_removed = 0u32;
    let mut expanded_state_write_bytes_removed = 0u64;
    let mut expanded_state_reread_bytes_removed = 0u64;
    let mut expansion_scratch_read_bytes_removed = 0u64;
    let mut expansion_scratch_write_bytes_removed = 0u64;
    let mut saw_finalize = false;

    for step in fused.steps() {
        let operation = match step.operation {
            FusedCompactDomainOperation::LdeBatch { .. } => continue,
            FusedCompactDomainOperation::AbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                log_size,
                initializes_state,
                reconstructed_tail,
                state: expected_state,
                ..
            } => {
                let batch = exact_terminal_batch(
                    batch_mode(batch_index)?,
                    first_column,
                    columns,
                    log_size,
                )?;
                if !seen.insert(batch_index) {
                    return Err(DirectTerminalExpandAbsorbError::DuplicateBatch(batch_index));
                }
                if expected_state.len_words != state(bank, log_size)?.len_words {
                    return Err(DirectTerminalExpandAbsorbError::InvalidState);
                }
                DirectTerminalExpandAbsorbOperation::Batch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    mode: batch.mode,
                    initializes_state,
                    reconstructed_tail,
                    transition: DirectTerminalExpandAbsorbTransition::None {
                        state: state(bank, log_size)?,
                    },
                }
            }
            FusedCompactDomainOperation::ExpandAbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                from_log_size,
                to_log_size,
                absorbed_columns_before: _,
                expansion_bands,
                reconstructed_tail,
                source_state,
                destination_state,
                ..
            } => {
                let batch = exact_terminal_batch(
                    batch_mode(batch_index)?,
                    first_column,
                    columns,
                    to_log_size,
                )?;
                if !seen.insert(batch_index) {
                    return Err(DirectTerminalExpandAbsorbError::DuplicateBatch(batch_index));
                }
                let transition = match batch.mode {
                    DirectCompactTerminalBatchMode::Materialized => {
                        let source = state(bank, from_log_size)?;
                        bank ^= 1;
                        let destination = state(bank, to_log_size)?;
                        if source.len_words != source_state.len_words
                            || destination.len_words != destination_state.len_words
                        {
                            return Err(DirectTerminalExpandAbsorbError::InvalidState);
                        }
                        let receipt = fused
                            .receipt()
                            .transitions
                            .iter()
                            .find(|transition| transition.batch_index == batch_index)
                            .ok_or(DirectTerminalExpandAbsorbError::InvalidBatch(batch_index))?;
                        fused_materialized_rises = fused_materialized_rises
                            .checked_add(1)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        kernel_launches_removed = kernel_launches_removed
                            .checked_add(receipt.kernel_launches_removed)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        device_copies_removed = device_copies_removed
                            .checked_add(receipt.device_copies_removed)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        expanded_state_write_bytes_removed = expanded_state_write_bytes_removed
                            .checked_add(receipt.expanded_state_write_bytes_removed)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        expanded_state_reread_bytes_removed = expanded_state_reread_bytes_removed
                            .checked_add(receipt.expanded_state_reread_bytes_removed)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        expansion_scratch_read_bytes_removed = expansion_scratch_read_bytes_removed
                            .checked_add(receipt.expansion_scratch_read_bytes_removed)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        expansion_scratch_write_bytes_removed =
                            expansion_scratch_write_bytes_removed
                                .checked_add(receipt.expansion_scratch_write_bytes_removed)
                                .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        DirectTerminalExpandAbsorbTransition::Materialized {
                            from_log_size,
                            to_log_size,
                            expansion_bands,
                            source_state: source,
                            destination_state: destination,
                            scratch,
                        }
                    }
                    DirectCompactTerminalBatchMode::Fixed16Hybrid { .. } => {
                        fixed16_rises = fixed16_rises
                            .checked_add(1)
                            .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
                        DirectTerminalExpandAbsorbTransition::Fixed16InPlace {
                            from_log_size,
                            to_log_size,
                            expansion_bands,
                            state: state(bank, to_log_size)?,
                            scratch,
                        }
                    }
                };
                DirectTerminalExpandAbsorbOperation::Batch {
                    batch_index,
                    first_column,
                    columns,
                    log_size: to_log_size,
                    mode: batch.mode,
                    initializes_state: false,
                    reconstructed_tail: Some(reconstructed_tail),
                    transition,
                }
            }
            FusedCompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                reconstructed_tail,
                state: expected_state,
                ..
            } => {
                if saw_finalize || bank != 0 {
                    return Err(DirectTerminalExpandAbsorbError::InvalidState);
                }
                saw_finalize = true;
                let state = state(bank, log_size)?;
                if state.offset_words != 0 || state.len_words != expected_state.len_words {
                    return Err(DirectTerminalExpandAbsorbError::InvalidState);
                }
                DirectTerminalExpandAbsorbOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    reconstructed_tail,
                    state,
                }
            }
        };
        operations.push(operation);
    }
    if !saw_finalize || seen.len() != terminal_batches.len() {
        return Err(DirectTerminalExpandAbsorbError::MissingFinalize);
    }
    let fixed16_batches = terminal_batches
        .iter()
        .filter(|batch| {
            matches!(
                batch.mode,
                DirectCompactTerminalBatchMode::Fixed16Hybrid { .. }
            )
        })
        .count()
        .try_into()
        .map_err(|_| DirectTerminalExpandAbsorbError::SizeOverflow)?;
    let materialized_batches = terminal_batches
        .len()
        .checked_sub(fixed16_batches as usize)
        .and_then(|count| u32::try_from(count).ok())
        .ok_or(DirectTerminalExpandAbsorbError::SizeOverflow)?;
    Ok(DirectTerminalExpandAbsorbProgram {
        operations,
        receipt: DirectTerminalExpandAbsorbReceipt {
            qualified_slab_capacity_words: qualified_words,
            state_bank_words: final_state_words,
            materialized_batches,
            fixed16_batches,
            fused_materialized_rises,
            fixed16_rises,
            kernel_launches_removed,
            device_copies_removed,
            expanded_state_write_bytes_removed,
            expanded_state_reread_bytes_removed,
            expansion_scratch_read_bytes_removed,
            expansion_scratch_write_bytes_removed,
            fixed16_terminal_receipt_unchanged: true,
            final_state_at_slab_zero: true,
            same_gpu_timing_credit_applied: false,
        },
    })
}

fn exact_terminal_batch<'a>(
    batch: &'a DirectCompactTerminalBatchReceipt,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<&'a DirectCompactTerminalBatchReceipt, DirectTerminalExpandAbsorbError> {
    if batch.first_column != first_column || batch.columns != columns || batch.log_size != log_size
    {
        return Err(DirectTerminalExpandAbsorbError::InvalidBatch(
            batch.batch_index,
        ));
    }
    Ok(batch)
}

#[cfg(test)]
#[path = "direct_terminal_expand_absorb_tests.rs"]
mod tests;
