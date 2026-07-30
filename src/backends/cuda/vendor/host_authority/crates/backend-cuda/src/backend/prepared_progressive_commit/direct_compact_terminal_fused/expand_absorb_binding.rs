//! Prepared binding for the mixed Fixed16/materialized-rise program.

use super::*;
use crate::backend::prepared_progressive_commit::domain_compact_binding::CompactOutputBatch;
use crate::backend::prepared_progressive_commit::{
    DirectTerminalExpandAbsorbOperation, DirectTerminalExpandAbsorbProgram,
    DirectTerminalExpandAbsorbTransition,
};

impl PreparedDirectCompactTerminalExecution {
    #[allow(clippy::too_many_arguments)]
    pub(in crate::backend::prepared_progressive_commit) fn bind_expand_absorb(
        program: &DirectTerminalExpandAbsorbProgram,
        terminal: DirectCompactTerminalProgram,
        prepared_batches: &[DirectPreparedBatch],
        plan: &ProgressiveCommitPlan,
        retained_outputs: &[Option<ArenaSlice>],
        slab: ArenaSlice,
        expected_scratch: ArenaSlice,
    ) -> Result<(Self, Vec<CompactStatePreparedLaunch>), DirectCompactTerminalError> {
        if program.receipt().fixed16_batches != terminal.receipt.fixed_terminal_launches
            || prepared_batches.len() != terminal.receipt.batches.len()
        {
            return Err(DirectCompactTerminalError::ProgramIdentity);
        }
        let mut steps = Vec::with_capacity(program.operations().len());
        let mut semantic = Vec::with_capacity(program.operations().len() * 2);
        for &operation in program.operations() {
            match operation {
                DirectTerminalExpandAbsorbOperation::Batch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    mode,
                    initializes_state,
                    reconstructed_tail,
                    transition,
                } => {
                    let batch = exact_prepared_batch(
                        prepared_batches,
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                    )?;
                    let receipt = terminal
                        .receipt
                        .batches
                        .get(batch_index as usize)
                        .filter(|receipt| {
                            receipt.batch_index == batch_index && receipt.mode == mode
                        })
                        .ok_or(DirectCompactTerminalError::PreparedBatch)?;
                    let (tail_columns, tail) = bind_tail_descriptor(
                        reconstructed_tail,
                        log_size,
                        first_column,
                        plan,
                        retained_outputs,
                    )?;
                    let output = CompactOutputBatch {
                        output_ptrs: batch.output_pointers,
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                    };
                    match transition {
                        DirectTerminalExpandAbsorbTransition::None { state } => {
                            let states = bind_state(slab, state, log_size)?;
                            let absorb = CompactStatePreparedLaunch::Absorb {
                                batch: output,
                                initializes_state,
                                tail_columns,
                                tail,
                                states,
                            };
                            semantic.push(absorb);
                            steps.push(bind_batch_step(
                                batch,
                                receipt.mode,
                                tail,
                                states,
                                None,
                                plan,
                                retained_outputs,
                            )?);
                        }
                        DirectTerminalExpandAbsorbTransition::Materialized {
                            from_log_size,
                            to_log_size,
                            expansion_bands: _,
                            source_state,
                            destination_state,
                            scratch,
                        } => {
                            if !matches!(mode, DirectCompactTerminalBatchMode::Materialized)
                                || initializes_state
                                || to_log_size != log_size
                            {
                                return Err(DirectCompactTerminalError::ProgramIdentity);
                            }
                            let source = bind_state(slab, source_state, from_log_size)?;
                            let destination = bind_state(slab, destination_state, to_log_size)?;
                            let scratch = bind_scratch(slab, scratch, expected_scratch)?;
                            validate_disjoint(source, destination, scratch)?;
                            semantic.push(CompactStatePreparedLaunch::Absorb {
                                batch: output,
                                initializes_state: false,
                                tail_columns,
                                tail,
                                states: destination,
                            });
                            steps.push(
                                PreparedDirectCompactTerminalStep::MaterializedExpandAbsorb {
                                    batch,
                                    from_log_size,
                                    to_log_size,
                                    absorbed_columns_before: first_column,
                                    tail,
                                    source_state: source,
                                    destination_state: destination,
                                },
                            );
                        }
                        DirectTerminalExpandAbsorbTransition::Fixed16InPlace {
                            from_log_size,
                            to_log_size,
                            expansion_bands,
                            state,
                            scratch,
                        } => {
                            if !matches!(mode, DirectCompactTerminalBatchMode::Fixed16Hybrid { .. })
                                || initializes_state
                                || to_log_size != log_size
                            {
                                return Err(DirectCompactTerminalError::ProgramIdentity);
                            }
                            let states = bind_state(slab, state, to_log_size)?;
                            let scratch_pair = bind_scratch(slab, scratch, expected_scratch)?;
                            validate_disjoint(states, scratch_pair, scratch_pair)?;
                            let expansion = CompactStatePreparedLaunch::ExpandInPlace {
                                from_log: from_log_size,
                                to_log: to_log_size,
                                absorbed_columns: first_column,
                                bands: expansion_bands,
                                states,
                                scratch_pair,
                            };
                            semantic.push(expansion);
                            semantic.push(CompactStatePreparedLaunch::Absorb {
                                batch: output,
                                initializes_state: false,
                                tail_columns,
                                tail,
                                states,
                            });
                            steps.push(bind_batch_step(
                                batch,
                                receipt.mode,
                                tail,
                                states,
                                Some(expansion),
                                plan,
                                retained_outputs,
                            )?);
                        }
                    }
                }
                DirectTerminalExpandAbsorbOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    reconstructed_tail,
                    state,
                } => {
                    let states_and_hashes = bind_state(slab, state, log_size)?;
                    if states_and_hashes.as_u32_ptr() != slab.as_u32_ptr() {
                        return Err(DirectCompactTerminalError::ProgramIdentity);
                    }
                    let (tail_columns, tail) = bind_tail_descriptor(
                        Some(reconstructed_tail),
                        log_size,
                        absorbed_columns,
                        plan,
                        retained_outputs,
                    )?;
                    let launch = CompactStatePreparedLaunch::FinalizeInPlace {
                        log_size,
                        absorbed_columns,
                        tail_columns,
                        tail,
                        states_and_hashes,
                    };
                    semantic.push(launch);
                    steps.push(PreparedDirectCompactTerminalStep::QualifiedState(launch));
                }
            }
        }
        Ok((
            Self {
                steps,
                receipt: terminal.receipt,
            },
            semantic,
        ))
    }
}

fn exact_prepared_batch(
    batches: &[DirectPreparedBatch],
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<DirectPreparedBatch, DirectCompactTerminalError> {
    batches
        .get(batch_index as usize)
        .copied()
        .filter(|batch| {
            batch.batch_index == batch_index
                && batch.first_column == first_column
                && batch.columns == columns
                && batch.retained_log_size == log_size
        })
        .ok_or(DirectCompactTerminalError::PreparedBatch)
}

#[allow(clippy::too_many_arguments)]
fn bind_batch_step(
    batch: DirectPreparedBatch,
    mode: DirectCompactTerminalBatchMode,
    tail: CompactBlake2sTailDescriptor,
    states: ArenaSlice,
    expansion: Option<CompactStatePreparedLaunch>,
    plan: &ProgressiveCommitPlan,
    retained_outputs: &[Option<ArenaSlice>],
) -> Result<PreparedDirectCompactTerminalStep, DirectCompactTerminalError> {
    match mode {
        DirectCompactTerminalBatchMode::Materialized if expansion.is_none() => {
            Ok(PreparedDirectCompactTerminalStep::Materialized {
                batch,
                absorb: CompactStatePreparedLaunch::Absorb {
                    batch: CompactOutputBatch {
                        output_ptrs: batch.output_pointers,
                        batch_index: batch.batch_index,
                        first_column: batch.first_column,
                        columns: batch.columns,
                        log_size: batch.retained_log_size,
                    },
                    initializes_state: batch.first_column == 0,
                    tail_columns: stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(
                        batch.first_column,
                    ),
                    tail,
                    states,
                },
            })
        }
        DirectCompactTerminalBatchMode::Materialized => {
            Err(DirectCompactTerminalError::ProgramIdentity)
        }
        DirectCompactTerminalBatchMode::Fixed16Hybrid {
            fixed_columns,
            tiles,
            generic_remainder_columns,
        } => {
            if fixed_columns == 0
                || fixed_columns.checked_add(generic_remainder_columns) != Some(batch.columns)
                || tiles.checked_mul(16) != Some(fixed_columns)
            {
                return Err(DirectCompactTerminalError::PreparedBatch);
            }
            let absorbed_after_fixed = batch
                .first_column
                .checked_add(fixed_columns)
                .ok_or(DirectCompactTerminalError::SizeOverflow)?;
            let remainder_tail = if generic_remainder_columns == 0 {
                None
            } else {
                let columns = stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(
                    absorbed_after_fixed,
                );
                Some(
                    bind_tail_descriptor(
                        Some(CompactDomainTail {
                            first_column: absorbed_after_fixed
                                .checked_sub(columns)
                                .ok_or(DirectCompactTerminalError::SizeOverflow)?,
                            columns,
                        }),
                        batch.retained_log_size,
                        absorbed_after_fixed,
                        plan,
                        retained_outputs,
                    )?
                    .1,
                )
            };
            Ok(PreparedDirectCompactTerminalStep::Fixed16Hybrid {
                batch,
                expansion,
                fixed_columns,
                tiles,
                remainder_columns: generic_remainder_columns,
                initial_tail: tail,
                remainder_tail,
                states,
            })
        }
    }
}

fn bind_state(
    slab: ArenaSlice,
    model: DomainCooperativeSlabSlice,
    log_size: u32,
) -> Result<ArenaSlice, DirectCompactTerminalError> {
    let expected = 1usize
        .checked_shl(log_size)
        .and_then(|rows| rows.checked_mul(HASH_WORDS))
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    if model.len_words != expected || model.offset_words % HASH_WORDS != 0 {
        return Err(DirectCompactTerminalError::ProgramIdentity);
    }
    slab.checked_subslice(model.offset_words, model.len_words)
        .map_err(CompactDomainBindingError::from)
        .map_err(DirectCompactTerminalError::from)
}

fn bind_scratch(
    slab: ArenaSlice,
    model: DomainCooperativeSlabSlice,
    expected: ArenaSlice,
) -> Result<ArenaSlice, DirectCompactTerminalError> {
    let bound = slab
        .checked_subslice(model.offset_words, model.len_words)
        .map_err(CompactDomainBindingError::from)?;
    if bound.id() != expected.id()
        || bound.as_u32_ptr() != expected.as_u32_ptr()
        || bound.len_words() != expected.len_words()
    {
        return Err(DirectCompactTerminalError::ProgramIdentity);
    }
    Ok(bound)
}

fn validate_disjoint(
    left: ArenaSlice,
    right: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<(), DirectCompactTerminalError> {
    let range = |slice: ArenaSlice| {
        let start = slice.as_u32_ptr() as usize;
        let bytes = slice
            .len_words()
            .checked_mul(core::mem::size_of::<u32>())
            .ok_or(DirectCompactTerminalError::SizeOverflow)?;
        Ok::<_, DirectCompactTerminalError>((
            start,
            start
                .checked_add(bytes)
                .ok_or(DirectCompactTerminalError::SizeOverflow)?,
        ))
    };
    let [left, right, scratch] = [range(left)?, range(right)?, range(scratch)?];
    let overlap = |a: (usize, usize), b: (usize, usize)| a.0 < b.1 && b.0 < a.1;
    if overlap(left, right)
        || (right != scratch && overlap(left, scratch))
        || (right != scratch && overlap(right, scratch))
    {
        return Err(DirectCompactTerminalError::ProgramIdentity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "expand_absorb_binding_tests.rs"]
mod tests;
