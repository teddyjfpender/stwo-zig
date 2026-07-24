//! Exact fixed16 terminal N2B plus compact-h8 execution.
//! Profitable log>=13 fixed-width prefixes stop before the final configured
//! N2B interval; one candidate sink completes it, writes canonical retained
//! evaluations, and advances compact state. A profitable non-16 remainder
//! uses the paired circle sink. Every other batch executes the materialized
//! path in the same program order. Expansion, finalization, and Merkle remain
//! the existing qualified launches. Selection is explicit: callers compile a
//! pure program, inspect its exact receipt, then consume that sealed program at
//! the prepared binding boundary. The materialized binding remains separate.

use super::direct_retained_b2n::PreparedBatch as DirectPreparedBatch;
use super::domain_compact_binding::{bind_tail_descriptor, CompactStatePreparedLaunch};
use super::*;

mod accounting;
mod expand_absorb_binding;
pub use accounting::*;
use accounting::{
    admit_batch, batch_mode, batch_receipt, checked_sum, checked_sum_i32, checked_sum_u32, fallback,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectCompactTerminalOperation {
    Batch {
        batch_index: u32,
        expected: CompactDomainPreparedLaunchKind,
        mode: DirectCompactTerminalBatchMode,
    },
    QualifiedState {
        expected: CompactDomainPreparedLaunchKind,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCompactTerminalProgram {
    operations: Vec<DirectCompactTerminalOperation>,
    receipt: DirectCompactTerminalReceipt,
}

impl DirectCompactTerminalProgram {
    /// Seal terminal-fusion eligibility and its exact traffic/write receipt
    /// without allocating CUDA resources or selecting a fallback graph.
    pub fn compile(
        compact: &CompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
    ) -> Result<Self, DirectCompactTerminalError> {
        Self::compile_steps(compact.steps(), direct.batches())
    }

    pub fn validate_against(
        &self,
        compact: &CompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
    ) -> Result<(), DirectCompactTerminalError> {
        if *self == Self::compile(compact, direct)? {
            Ok(())
        } else {
            Err(DirectCompactTerminalError::ProgramIdentity)
        }
    }

    pub fn receipt(&self) -> &DirectCompactTerminalReceipt {
        &self.receipt
    }

    fn compile_steps(
        steps: &[CompactDomainStep],
        batches: &[DirectRetainedB2nBatchPlan],
    ) -> Result<Self, DirectCompactTerminalError> {
        let support = DirectCompactTerminalSupport::default();
        let canonical_logs = canonical_logs(batches)?;
        let mut operations = Vec::with_capacity(steps.len().saturating_sub(batches.len()));
        let mut receipts = Vec::with_capacity(batches.len());
        let mut expansion_launches = 0u32;
        let mut finalize_launches = 0u32;
        let mut lde_steps = vec![None; batches.len()];

        for (step_index, step) in steps.iter().enumerate() {
            let CompactDomainOperation::LdeBatch {
                batch_index,
                first_column,
                columns,
                log_size,
            } = step.operation
            else {
                continue;
            };
            exact_batch(batches, batch_index, first_column, columns, log_size)?;
            admit_batch(log_size, columns, support)?;
            let slot = lde_steps
                .get_mut(batch_index as usize)
                .ok_or_else(|| fallback(DirectCompactTerminalFallbackReason::NonCanonicalBatch))?;
            if slot.replace(step_index).is_some() {
                return Err(fallback(
                    DirectCompactTerminalFallbackReason::NonCanonicalBatch,
                ));
            }
        }
        if lde_steps.iter().any(Option::is_none) {
            return Err(fallback(
                DirectCompactTerminalFallbackReason::NonAdjacentAbsorb,
            ));
        }

        for (step_index, step) in steps.iter().enumerate() {
            match step.operation {
                CompactDomainOperation::LdeBatch { .. } => {}
                CompactDomainOperation::AbsorbDomainBatch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                    initializes_state,
                    reconstructed_tail,
                    ..
                } => {
                    let batch = exact_batch(batches, batch_index, first_column, columns, log_size)?;
                    let lde_step = lde_steps
                        .get(batch_index as usize)
                        .copied()
                        .flatten()
                        .ok_or_else(|| {
                            fallback(DirectCompactTerminalFallbackReason::NonAdjacentAbsorb)
                        })?;
                    if lde_step >= step_index {
                        return Err(fallback(
                            DirectCompactTerminalFallbackReason::NonAdjacentAbsorb,
                        ));
                    }
                    if batch_index as usize != receipts.len()
                        || absorbed_columns_before != first_column
                    {
                        return Err(fallback(
                            DirectCompactTerminalFallbackReason::NonCanonicalBatch,
                        ));
                    }
                    if !stwo_backend_cuda_kernels::raw::blake2s_compact_absorb_counts_valid(
                        columns,
                        absorbed_columns_before,
                        initializes_state,
                    ) {
                        return Err(fallback(
                            DirectCompactTerminalFallbackReason::CounterOverflow,
                        ));
                    }
                    validate_tail(reconstructed_tail, first_column, log_size, &canonical_logs)?;
                    let mode = batch_mode(first_column, log_size, columns);
                    let tail_columns = reconstructed_tail.map_or(0, |tail| tail.columns);
                    let expected = CompactDomainPreparedLaunchKind::AbsorbDomainBatch {
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                        absorbed_columns_before,
                        initializes_state,
                        tail_columns,
                    };
                    operations.push(DirectCompactTerminalOperation::Batch {
                        batch_index,
                        expected,
                        mode,
                    });
                    receipts.push(batch_receipt(batch, mode)?);
                }
                CompactDomainOperation::StateExpandInPlace {
                    from_log_size,
                    to_log_size,
                    absorbed_columns,
                    bands,
                } => {
                    operations.push(DirectCompactTerminalOperation::QualifiedState {
                        expected: CompactDomainPreparedLaunchKind::StateExpandInPlace {
                            from_log_size,
                            to_log_size,
                            absorbed_columns,
                            bands,
                        },
                    });
                    expansion_launches = expansion_launches
                        .checked_add(1)
                        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                }
                CompactDomainOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    reconstructed_tail,
                    ..
                } => {
                    validate_tail(
                        Some(reconstructed_tail),
                        absorbed_columns,
                        log_size,
                        &canonical_logs,
                    )?;
                    operations.push(DirectCompactTerminalOperation::QualifiedState {
                        expected: CompactDomainPreparedLaunchKind::FinalizeInPlace {
                            log_size,
                            absorbed_columns,
                            tail_columns: reconstructed_tail.columns,
                        },
                    });
                    finalize_launches = finalize_launches
                        .checked_add(1)
                        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                }
            }
        }
        if receipts.len() != batches.len() {
            return Err(fallback(
                DirectCompactTerminalFallbackReason::NonCanonicalBatch,
            ));
        }
        let removed_reread_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.separate_absorb_reread_bytes_removed),
        )?;
        let added_prefinal_read_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.terminal_prefinal_read_bytes_added),
        )?;
        let added_tail_read_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.compact_tail_reread_bytes_added),
        )?;
        let net_read_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.net_read_bytes_removed),
        )?;
        let added_prefinal_write_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.terminal_prefinal_write_bytes_added),
        )?;
        let net_device_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.net_device_bytes_removed),
        )?;
        let retained_bytes = checked_sum(
            receipts
                .iter()
                .map(|receipt| receipt.canonical_retained_write_bytes),
        )?;
        let removed_absorbs = checked_sum_u32(
            receipts
                .iter()
                .map(|receipt| receipt.separate_absorb_launches_removed),
        )?;
        let fixed_launches = checked_sum_u32(
            receipts
                .iter()
                .map(|receipt| receipt.fixed_terminal_launches),
        )?;
        let remainder_intervals = checked_sum_u32(
            receipts
                .iter()
                .map(|receipt| receipt.extra_remainder_interval_launches),
        )?;
        let remainder_terminals = checked_sum_u32(
            receipts
                .iter()
                .map(|receipt| receipt.generic_remainder_terminal_launches),
        )?;
        let net_launches = checked_sum_i32(
            receipts
                .iter()
                .map(|receipt| receipt.net_cuda_launches_removed),
        )?;
        let cooperative_quad_batches = receipts
            .iter()
            .filter(|receipt| receipt.cooperative_quad_blake2s_sink)
            .count()
            .try_into()
            .map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
        Ok(Self {
            operations,
            receipt: DirectCompactTerminalReceipt {
                support,
                batches: receipts,
                separate_absorb_reread_bytes_removed: removed_reread_bytes,
                terminal_prefinal_read_bytes_added: added_prefinal_read_bytes,
                compact_tail_reread_bytes_added: added_tail_read_bytes,
                net_read_bytes_removed: net_read_bytes,
                terminal_prefinal_write_bytes_added: added_prefinal_write_bytes,
                net_device_bytes_removed: net_device_bytes,
                canonical_retained_write_bytes_before: retained_bytes,
                canonical_retained_write_bytes_after: retained_bytes,
                separate_absorb_launches_removed: removed_absorbs,
                fixed_terminal_launches: fixed_launches,
                extra_remainder_interval_launches: remainder_intervals,
                generic_remainder_terminal_launches: remainder_terminals,
                net_cuda_launches_removed: net_launches,
                cooperative_quad_blake2s_batches: cooperative_quad_batches,
                compact_expansion_launches_unchanged: expansion_launches,
                compact_finalize_launches_unchanged: finalize_launches,
                merkle_suffix_unchanged: true,
                same_gpu_timing_credit_applied: false,
            },
        })
    }
}

#[derive(Clone, Copy)]
enum PreparedDirectCompactTerminalStep {
    Materialized {
        batch: DirectPreparedBatch,
        absorb: CompactStatePreparedLaunch,
    },
    MaterializedExpandAbsorb {
        batch: DirectPreparedBatch,
        from_log_size: u32,
        to_log_size: u32,
        absorbed_columns_before: u32,
        tail: CompactBlake2sTailDescriptor,
        source_state: ArenaSlice,
        destination_state: ArenaSlice,
    },
    Fixed16Hybrid {
        batch: DirectPreparedBatch,
        expansion: Option<CompactStatePreparedLaunch>,
        fixed_columns: u32,
        tiles: u32,
        remainder_columns: u32,
        initial_tail: CompactBlake2sTailDescriptor,
        remainder_tail: Option<CompactBlake2sTailDescriptor>,
        states: ArenaSlice,
    },
    QualifiedState(CompactStatePreparedLaunch),
}

pub(super) struct PreparedDirectCompactTerminalExecution {
    steps: Vec<PreparedDirectCompactTerminalStep>,
    receipt: DirectCompactTerminalReceipt,
}

impl PreparedDirectCompactTerminalExecution {
    fn bind(
        program: DirectCompactTerminalProgram,
        prepared_batches: &[DirectPreparedBatch],
        state_launches: &[CompactStatePreparedLaunch],
        plan: &ProgressiveCommitPlan,
        retained_outputs: &[Option<ArenaSlice>],
    ) -> Result<Self, DirectCompactTerminalError> {
        if program.operations.len() != state_launches.len() {
            return Err(DirectCompactTerminalError::PreparedBatch);
        }
        let mut steps = Vec::with_capacity(program.operations.len());
        for (operation, launch) in program
            .operations
            .iter()
            .copied()
            .zip(state_launches.iter().copied())
        {
            match operation {
                DirectCompactTerminalOperation::Batch {
                    batch_index,
                    expected,
                    mode,
                } => {
                    if launch.kind() != expected {
                        return Err(DirectCompactTerminalError::PreparedBatch);
                    }
                    let CompactStatePreparedLaunch::Absorb {
                        initializes_state,
                        tail,
                        states,
                        ..
                    } = launch
                    else {
                        return Err(DirectCompactTerminalError::PreparedBatch);
                    };
                    let batch = prepared_batches
                        .get(batch_index as usize)
                        .copied()
                        .filter(|batch| batch.batch_index == batch_index)
                        .ok_or(DirectCompactTerminalError::PreparedBatch)?;
                    if initializes_state != (batch.first_column == 0) {
                        return Err(DirectCompactTerminalError::PreparedBatch);
                    }
                    match mode {
                        DirectCompactTerminalBatchMode::Materialized => {
                            steps.push(PreparedDirectCompactTerminalStep::Materialized {
                                batch,
                                absorb: launch,
                            });
                        }
                        DirectCompactTerminalBatchMode::Fixed16Hybrid {
                            fixed_columns,
                            tiles,
                            generic_remainder_columns,
                        } => {
                            if fixed_columns == 0
                                || fixed_columns.checked_add(generic_remainder_columns)
                                    != Some(batch.columns)
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
                                let tail_columns =
                                    stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(
                                        absorbed_after_fixed,
                                    );
                                let tail_spec = CompactDomainTail {
                                    first_column: absorbed_after_fixed
                                        .checked_sub(tail_columns)
                                        .ok_or(DirectCompactTerminalError::SizeOverflow)?,
                                    columns: tail_columns,
                                };
                                Some(
                                    bind_tail_descriptor(
                                        Some(tail_spec),
                                        batch.retained_log_size,
                                        absorbed_after_fixed,
                                        plan,
                                        retained_outputs,
                                    )?
                                    .1,
                                )
                            };
                            steps.push(PreparedDirectCompactTerminalStep::Fixed16Hybrid {
                                batch,
                                expansion: None,
                                fixed_columns,
                                tiles,
                                remainder_columns: generic_remainder_columns,
                                initial_tail: tail,
                                remainder_tail,
                                states,
                            });
                        }
                    }
                }
                DirectCompactTerminalOperation::QualifiedState { expected } => {
                    if launch.kind() != expected
                        || matches!(launch, CompactStatePreparedLaunch::Absorb { .. })
                    {
                        return Err(DirectCompactTerminalError::PreparedBatch);
                    }
                    steps.push(PreparedDirectCompactTerminalStep::QualifiedState(launch));
                }
            }
        }
        Ok(Self {
            steps,
            receipt: program.receipt,
        })
    }

    pub(super) fn configure(&self) -> Result<(), DirectCompactTerminalError> {
        let mut configured = std::collections::BTreeSet::new();
        for step in &self.steps {
            let PreparedDirectCompactTerminalStep::Fixed16Hybrid { batch, .. } = *step else {
                continue;
            };
            if configured.insert(batch.retained_log_size) {
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_ntt_direct_compact_final16_col8_configure(
                        batch.retained_log_size,
                    )
                };
                check_cuda("direct_compact_final16_col8_configure", code)
                    .map_err(CompactDomainBindingError::from)?;
            }
        }
        Ok(())
    }

    pub(super) fn launch(
        &self,
        direct: &PreparedDirectRetainedB2nGraph<'_>,
        arena: &DeviceArena,
    ) -> Result<(), DirectCompactTerminalError> {
        let stream = arena.context().stream_raw().as_ptr();
        let (twiddles, twiddle_words) = direct.forward_twiddles();
        for step in &self.steps {
            match *step {
                PreparedDirectCompactTerminalStep::Materialized { batch, absorb } => {
                    direct.launch_batch_materialized(batch.batch_index)?;
                    absorb.launch(arena)?;
                }
                PreparedDirectCompactTerminalStep::MaterializedExpandAbsorb {
                    batch,
                    from_log_size,
                    to_log_size,
                    absorbed_columns_before,
                    tail,
                    source_state,
                    destination_state,
                } => {
                    direct.launch_batch_materialized(batch.batch_index)?;
                    let code = unsafe {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_compact_expand_absorb_quad_on(
                            from_log_size,
                            to_log_size,
                            batch.columns,
                            absorbed_columns_before,
                            batch.output_pointers.as_u32_ptr().cast(),
                            &tail,
                            source_state.as_u32_ptr().cast(),
                            destination_state.as_u32_ptr().cast(),
                            stream,
                        )
                    };
                    check_cuda("direct_compact_expand_absorb", code)
                        .map_err(CompactDomainBindingError::from)?;
                }
                PreparedDirectCompactTerminalStep::Fixed16Hybrid {
                    batch,
                    expansion,
                    fixed_columns,
                    tiles,
                    remainder_columns,
                    initial_tail,
                    remainder_tail,
                    states,
                } => {
                    if let Some(expansion) = expansion {
                        expansion.launch(arena)?;
                    }
                    direct.launch_batch_before_final_interval(batch.batch_index)?;
                    let size = 1u32
                        .checked_shl(batch.retained_log_size)
                        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                    let eval_domain_size = size / 2;
                    let code = unsafe {
                        stwo_backend_cuda_kernels::raw::stwo_ntt_direct_compact_final16_col8_on(
                            batch.output_pointers.as_u32_ptr().cast(),
                            batch.retained_log_size,
                            tiles,
                            twiddles.as_u32_ptr(),
                            twiddle_words,
                            eval_domain_size,
                            batch.first_column,
                            &initial_tail,
                            states.as_u32_ptr().cast(),
                            stream,
                        )
                    };
                    check_cuda("direct_compact_final16_col8", code)
                        .map_err(CompactDomainBindingError::from)?;
                    if remainder_columns != 0 {
                        let pointers = direct.launch_final_interval_before_circle(
                            batch.batch_index,
                            fixed_columns,
                            remainder_columns,
                        )?;
                        let tail =
                            remainder_tail.ok_or(DirectCompactTerminalError::PreparedBatch)?;
                        let absorbed = batch
                            .first_column
                            .checked_add(fixed_columns)
                            .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                        let code = unsafe {
                            stwo_backend_cuda_kernels::raw::
                                stwo_blake2s_compact_absorb_n2b_terminal_pair_on(
                                    size,
                                    remainder_columns,
                                    absorbed,
                                    pointers.as_u32_ptr().cast(),
                                    0,
                                    &tail,
                                    twiddles.as_u32_ptr(),
                                    twiddle_words,
                                    states.as_u32_ptr().cast(),
                                    stream,
                                )
                        };
                        check_cuda("direct_compact_n2b_remainder", code)
                            .map_err(CompactDomainBindingError::from)?;
                    }
                }
                PreparedDirectCompactTerminalStep::QualifiedState(launch) => {
                    launch.launch(arena)?;
                }
            }
        }
        Ok(())
    }

    pub(super) fn receipt(&self) -> &DirectCompactTerminalReceipt {
        &self.receipt
    }
}

impl CompactDomainProgram {
    /// Bind a caller-selected terminal fusion program. Call
    /// [`Self::bind_prepared_direct`] for the explicit materialized path when
    /// pure admission rejects a shape or the caller declines its receipt.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_prepared_direct_terminal_fused<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        direct_program: &DirectRetainedB2nProgram,
        terminal: DirectCompactTerminalProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        columns: &[DirectRetainedB2nColumn],
        inverse_twiddles: ArenaSlice,
        forward_twiddles: ArenaSlice,
    ) -> Result<PreparedDirectCompactDomainCommitGraph<'a>, DirectCompactDomainBindingError> {
        terminal.validate_against(self, direct_program)?;
        let mut graph = self.bind_prepared_direct(
            arena,
            base,
            domain,
            direct_program,
            slots,
            columns,
            inverse_twiddles,
            forward_twiddles,
        )?;
        graph.direct.validate_terminal_output_disjoint()?;
        let execution = PreparedDirectCompactTerminalExecution::bind(
            terminal,
            graph.direct.prepared_batches(),
            &graph.leaves.launches,
            &base.requirements().leaves.plan,
            graph.retained_evaluations(),
        )?;
        execution.configure()?;
        graph.terminal = Some(execution);
        Ok(graph)
    }
}

fn canonical_logs(
    batches: &[DirectRetainedB2nBatchPlan],
) -> Result<Vec<u32>, DirectCompactTerminalError> {
    let columns = batches
        .iter()
        .map(|batch| batch.canonical_columns.len())
        .try_fold(0usize, |total, width| total.checked_add(width))
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    let mut logs = vec![u32::MAX; columns];
    for batch in batches {
        for &canonical in &batch.canonical_columns {
            let Some(slot) = logs.get_mut(canonical) else {
                return Err(fallback(
                    DirectCompactTerminalFallbackReason::NonCanonicalBatch,
                ));
            };
            if *slot != u32::MAX {
                return Err(fallback(
                    DirectCompactTerminalFallbackReason::NonCanonicalBatch,
                ));
            }
            *slot = batch.retained_log_size;
        }
    }
    if logs.contains(&u32::MAX) {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::NonCanonicalBatch,
        ));
    }
    Ok(logs)
}

fn exact_batch(
    batches: &[DirectRetainedB2nBatchPlan],
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<&DirectRetainedB2nBatchPlan, DirectCompactTerminalError> {
    let batch = batches
        .get(batch_index as usize)
        .filter(|batch| batch.batch_index == batch_index)
        .ok_or_else(|| fallback(DirectCompactTerminalFallbackReason::NonCanonicalBatch))?;
    let expected_first = batch.canonical_columns.first().copied();
    let expected_columns = u32::try_from(batch.canonical_columns.len())
        .map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
    let first =
        usize::try_from(first_column).map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
    let width = usize::try_from(columns).map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
    let end = first
        .checked_add(width)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    if expected_first != Some(first)
        || expected_columns != columns
        || batch.retained_log_size != log_size
        || batch.canonical_columns != (first..end).collect::<Vec<_>>()
    {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::NonCanonicalBatch,
        ));
    }
    Ok(batch)
}

fn validate_tail(
    tail: Option<CompactDomainTail>,
    absorbed_columns: u32,
    target_log_size: u32,
    canonical_logs: &[u32],
) -> Result<(), DirectCompactTerminalError> {
    let expected = stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(absorbed_columns);
    if expected == 0 {
        return if tail.is_none() {
            Ok(())
        } else {
            Err(fallback(
                DirectCompactTerminalFallbackReason::InvalidTailLift,
            ))
        };
    }
    let Some(tail) = tail else {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::InvalidTailLift,
        ));
    };
    let end = tail
        .first_column
        .checked_add(tail.columns)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    if tail.columns != expected || end != absorbed_columns {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::InvalidTailLift,
        ));
    }
    for canonical in tail.first_column..end {
        let Some(&log_size) = canonical_logs.get(canonical as usize) else {
            return Err(fallback(
                DirectCompactTerminalFallbackReason::InvalidTailLift,
            ));
        };
        if log_size > target_log_size {
            return Err(fallback(
                DirectCompactTerminalFallbackReason::InvalidTailLift,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "direct_compact_terminal_fused_tests.rs"]
mod tests;
