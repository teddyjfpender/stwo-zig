use super::*;

pub(super) const MIN_TERMINAL_LOG_SIZE: u32 = 4;
pub(super) const MIN_FIXED16_LOG_SIZE: u32 = 13;
pub(super) const MAX_TERMINAL_LOG_SIZE: u32 = 30;
pub(super) const MAX_TERMINAL_BATCH_COLUMNS: u32 = 65_535;
const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectCompactTerminalSupport {
    pub min_log_size: u32,
    pub min_fixed16_log_size: u32,
    pub max_log_size: u32,
    pub max_batch_columns: u32,
    pub fixed_tile_columns: u32,
    pub requires_blowup_two: bool,
    pub requires_pairwise_disjoint_outputs: bool,
    pub requires_canonical_prefinal_inputs: bool,
    pub requires_canonical_twiddles: bool,
    pub requires_cuda_byte_parity: bool,
    pub requires_narrow_sass_gate: bool,
    pub requires_register_spill_stack_gate: bool,
    pub requires_cooperative_quad_blake2s_resource_gate: bool,
}

impl Default for DirectCompactTerminalSupport {
    fn default() -> Self {
        Self {
            min_log_size: MIN_TERMINAL_LOG_SIZE,
            min_fixed16_log_size: MIN_FIXED16_LOG_SIZE,
            max_log_size: MAX_TERMINAL_LOG_SIZE,
            max_batch_columns: MAX_TERMINAL_BATCH_COLUMNS,
            fixed_tile_columns: 16,
            requires_blowup_two: true,
            requires_pairwise_disjoint_outputs: true,
            requires_canonical_prefinal_inputs: true,
            requires_canonical_twiddles: true,
            requires_cuda_byte_parity: true,
            requires_narrow_sass_gate: true,
            requires_register_spill_stack_gate: true,
            requires_cooperative_quad_blake2s_resource_gate: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectCompactTerminalFallbackReason {
    UnsupportedLogSize(u32),
    UnsupportedBatchWidth(u32),
    CounterOverflow,
    NonCanonicalBatch,
    NonAdjacentAbsorb,
    InvalidTailLift,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectCompactTerminalBatchMode {
    Materialized,
    Fixed16Hybrid {
        fixed_columns: u32,
        tiles: u32,
        generic_remainder_columns: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectCompactTerminalBatchReceipt {
    pub batch_index: u32,
    pub first_column: u32,
    pub columns: u32,
    pub log_size: u32,
    pub mode: DirectCompactTerminalBatchMode,
    pub separate_absorb_reread_bytes_removed: u64,
    pub terminal_prefinal_read_bytes_added: u64,
    pub compact_tail_reread_bytes_added: u64,
    pub net_read_bytes_removed: u64,
    pub terminal_prefinal_write_bytes_added: u64,
    pub net_device_bytes_removed: u64,
    pub canonical_retained_write_bytes: u64,
    pub separate_absorb_launches_removed: u32,
    pub final_interval_launches_replaced: u32,
    pub fixed_terminal_launches: u32,
    pub extra_remainder_interval_launches: u32,
    pub generic_remainder_terminal_launches: u32,
    pub net_cuda_launches_removed: i32,
    pub cooperative_quad_blake2s_sink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectCompactTerminalReceipt {
    pub support: DirectCompactTerminalSupport,
    pub batches: Vec<DirectCompactTerminalBatchReceipt>,
    pub separate_absorb_reread_bytes_removed: u64,
    pub terminal_prefinal_read_bytes_added: u64,
    pub compact_tail_reread_bytes_added: u64,
    pub net_read_bytes_removed: u64,
    pub terminal_prefinal_write_bytes_added: u64,
    pub net_device_bytes_removed: u64,
    pub canonical_retained_write_bytes_before: u64,
    pub canonical_retained_write_bytes_after: u64,
    pub separate_absorb_launches_removed: u32,
    pub fixed_terminal_launches: u32,
    pub extra_remainder_interval_launches: u32,
    pub generic_remainder_terminal_launches: u32,
    pub net_cuda_launches_removed: i32,
    pub cooperative_quad_blake2s_batches: u32,
    pub compact_expansion_launches_unchanged: u32,
    pub compact_finalize_launches_unchanged: u32,
    pub merkle_suffix_unchanged: bool,
    pub same_gpu_timing_credit_applied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectCompactTerminalError {
    Fallback(DirectCompactTerminalFallbackReason),
    ProgramIdentity,
    SizeOverflow,
    PreparedBatch,
    Launch(DirectRetainedB2nError),
    Compact(CompactDomainBindingError),
}

impl core::fmt::Display for DirectCompactTerminalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid direct compact terminal fusion: {self:?}")
    }
}

impl std::error::Error for DirectCompactTerminalError {}

impl From<DirectRetainedB2nError> for DirectCompactTerminalError {
    fn from(value: DirectRetainedB2nError) -> Self {
        Self::Launch(value)
    }
}

impl From<CompactDomainBindingError> for DirectCompactTerminalError {
    fn from(value: CompactDomainBindingError) -> Self {
        Self::Compact(value)
    }
}

pub(super) fn admit_batch(
    log_size: u32,
    columns: u32,
    support: DirectCompactTerminalSupport,
) -> Result<(), DirectCompactTerminalError> {
    if !(support.min_log_size..=support.max_log_size).contains(&log_size) {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::UnsupportedLogSize(log_size),
        ));
    }
    if columns == 0 || columns > support.max_batch_columns {
        return Err(fallback(
            DirectCompactTerminalFallbackReason::UnsupportedBatchWidth(columns),
        ));
    }
    Ok(())
}

pub(super) fn batch_mode(
    first_column: u32,
    log_size: u32,
    columns: u32,
) -> DirectCompactTerminalBatchMode {
    if !column8_terminal_supported(log_size) || columns < 16 {
        return DirectCompactTerminalBatchMode::Materialized;
    }
    let fixed_columns = columns / 16 * 16;
    let tiles = fixed_columns / 16;
    let remainder = columns - fixed_columns;
    let Some(absorbed_after_fixed) = first_column.checked_add(fixed_columns) else {
        return DirectCompactTerminalBatchMode::Materialized;
    };
    let tail_after_fixed =
        stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(absorbed_after_fixed);
    let tail_rereads = tail_after_fixed * ((tiles - 1) + u32::from(remainder != 0));
    let Some(net_read_words) = columns
        .checked_sub(remainder)
        .and_then(|words| words.checked_sub(tail_rereads))
    else {
        return DirectCompactTerminalBatchMode::Materialized;
    };
    if net_read_words <= remainder {
        return DirectCompactTerminalBatchMode::Materialized;
    }
    DirectCompactTerminalBatchMode::Fixed16Hybrid {
        fixed_columns,
        tiles,
        generic_remainder_columns: remainder,
    }
}

pub(super) const fn column8_terminal_supported(log_size: u32) -> bool {
    matches!(log_size, 13..=16 | 20..=24)
}

pub(super) fn batch_receipt(
    batch: &DirectRetainedB2nBatchPlan,
    mode: DirectCompactTerminalBatchMode,
) -> Result<DirectCompactTerminalBatchReceipt, DirectCompactTerminalError> {
    let columns = u64::try_from(batch.canonical_columns.len())
        .map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
    let rows = 1u64
        .checked_shl(batch.retained_log_size)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    let column_bytes = rows
        .checked_mul(WORD_BYTES)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    let retained_bytes = column_bytes
        .checked_mul(columns)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    let (removed_read, added_read, tail_read, added_write, removed_launches, remainder_launches) =
        match mode {
            DirectCompactTerminalBatchMode::Materialized => (0, 0, 0, 0, 0, 0),
            DirectCompactTerminalBatchMode::Fixed16Hybrid {
                tiles,
                fixed_columns,
                generic_remainder_columns,
            } => {
                let remainder_bytes = column_bytes
                    .checked_mul(u64::from(generic_remainder_columns))
                    .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                let first_column = u32::try_from(batch.canonical_columns[0])
                    .map_err(|_| DirectCompactTerminalError::SizeOverflow)?;
                let absorbed_after_fixed = first_column
                    .checked_add(fixed_columns)
                    .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                let tail_words = stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(
                    absorbed_after_fixed,
                );
                let tail_reads = tail_words
                    .checked_mul((tiles - 1) + u32::from(generic_remainder_columns != 0))
                    .and_then(|words| column_bytes.checked_mul(u64::from(words)))
                    .ok_or(DirectCompactTerminalError::SizeOverflow)?;
                (
                    retained_bytes,
                    remainder_bytes,
                    tail_reads,
                    remainder_bytes,
                    1,
                    u32::from(generic_remainder_columns != 0),
                )
            }
        };
    let net_read = removed_read
        .checked_sub(added_read)
        .and_then(|bytes| bytes.checked_sub(tail_read))
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    let net_device = net_read
        .checked_sub(added_write)
        .ok_or(DirectCompactTerminalError::SizeOverflow)?;
    Ok(DirectCompactTerminalBatchReceipt {
        batch_index: batch.batch_index,
        first_column: u32::try_from(batch.canonical_columns[0])
            .map_err(|_| DirectCompactTerminalError::SizeOverflow)?,
        columns: u32::try_from(batch.canonical_columns.len())
            .map_err(|_| DirectCompactTerminalError::SizeOverflow)?,
        log_size: batch.retained_log_size,
        mode,
        separate_absorb_reread_bytes_removed: removed_read,
        terminal_prefinal_read_bytes_added: added_read,
        compact_tail_reread_bytes_added: tail_read,
        net_read_bytes_removed: net_read,
        terminal_prefinal_write_bytes_added: added_write,
        net_device_bytes_removed: net_device,
        canonical_retained_write_bytes: retained_bytes,
        separate_absorb_launches_removed: removed_launches,
        final_interval_launches_replaced: removed_launches,
        fixed_terminal_launches: removed_launches,
        extra_remainder_interval_launches: remainder_launches,
        generic_remainder_terminal_launches: remainder_launches,
        net_cuda_launches_removed: removed_launches as i32 - 2 * remainder_launches as i32,
        cooperative_quad_blake2s_sink: removed_launches != 0,
    })
}

pub(super) fn checked_sum(
    mut values: impl Iterator<Item = u64>,
) -> Result<u64, DirectCompactTerminalError> {
    values
        .try_fold(0u64, |total, value| total.checked_add(value))
        .ok_or(DirectCompactTerminalError::SizeOverflow)
}

pub(super) fn checked_sum_u32(
    mut values: impl Iterator<Item = u32>,
) -> Result<u32, DirectCompactTerminalError> {
    values
        .try_fold(0u32, |total, value| total.checked_add(value))
        .ok_or(DirectCompactTerminalError::SizeOverflow)
}

pub(super) fn checked_sum_i32(
    mut values: impl Iterator<Item = i32>,
) -> Result<i32, DirectCompactTerminalError> {
    values
        .try_fold(0i32, |total, value| total.checked_add(value))
        .ok_or(DirectCompactTerminalError::SizeOverflow)
}

pub(super) const fn fallback(
    reason: DirectCompactTerminalFallbackReason,
) -> DirectCompactTerminalError {
    DirectCompactTerminalError::Fallback(reason)
}
