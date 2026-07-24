use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn validate_absorb(
    batches: &[Batch],
    absorbed_batches: usize,
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
    absorbed_columns_before: u32,
    absorbed_columns: u32,
    reconstructed_tail: Option<CompactDomainTail>,
    leaf_compressions: u64,
) -> Result<(), FusedCompactDomainProgramError> {
    let Some(batch) = batches.get(absorbed_batches) else {
        return Err(FusedCompactDomainProgramError::NonCanonicalBatch);
    };
    if *batch
        != (Batch {
            batch_index,
            first_column,
            columns,
            log_size,
        })
        || batch_index as usize != absorbed_batches
        || first_column != absorbed_columns
        || absorbed_columns_before != absorbed_columns
        || reconstructed_tail != canonical_tail(absorbed_columns)
    {
        return Err(FusedCompactDomainProgramError::NonCanonicalBatch);
    }
    let end = first_column
        .checked_add(columns)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let expected_compressions = u64::from(block_boundaries(first_column, end))
        .checked_mul(row_count(log_size)?)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    if leaf_compressions != expected_compressions {
        return Err(FusedCompactDomainProgramError::CompressionMismatch {
            current: leaf_compressions,
            fused: expected_compressions,
        });
    }
    Ok(())
}

pub(super) fn validate_absorb_traffic(
    traffic: CommitProgramTraffic,
    state: DomainCooperativeSlabSlice,
    columns: u32,
    tail: Option<CompactDomainTail>,
) -> Result<(), FusedCompactDomainProgramError> {
    let state_bytes = bytes(state.len_words)?;
    let rows = state.len_words / HASH_WORDS;
    let evaluation_bytes = u64::try_from(rows)
        .ok()
        .and_then(|rows| rows.checked_mul(u64::from(columns)))
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let tail_bytes = u64::try_from(rows)
        .ok()
        .and_then(|rows| rows.checked_mul(u64::from(tail.map_or(0, |tail| tail.columns))))
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let state_read = if tail.is_none() { 0 } else { state_bytes };
    let expected = CommitProgramTraffic {
        owned_read_bytes: state_read
            .checked_add(evaluation_bytes)
            .and_then(|bytes| bytes.checked_add(tail_bytes))
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: state_bytes,
        kernel_launches: 1,
        device_copies: 0,
    };
    if traffic != expected {
        return Err(FusedCompactDomainProgramError::NonCanonicalTraffic);
    }
    Ok(())
}

pub(super) fn fused_transition_traffic(
    step_index: usize,
    expansion: CompactDomainStep,
    absorb: CompactDomainStep,
    source: DomainCooperativeSlabSlice,
    destination: DomainCooperativeSlabSlice,
    columns: u32,
    tail: Option<CompactDomainTail>,
) -> Result<CommitProgramTraffic, FusedCompactDomainProgramError> {
    let CompactDomainOperation::StateExpandInPlace { bands, .. } = expansion.operation else {
        return Err(FusedCompactDomainProgramError::ExpansionAbsorbMismatch { step: step_index });
    };
    let source_bytes = bytes(source.len_words)?;
    let destination_bytes = bytes(destination.len_words)?;
    let scratch_bytes = COMPACT_EXPANSION_SCRATCH_HASHES
        .checked_mul(HASH_BYTES)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let expected_expansion = CommitProgramTraffic {
        owned_read_bytes: source_bytes
            .checked_add(scratch_bytes)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: destination_bytes
            .checked_add(scratch_bytes)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        kernel_launches: bands,
        device_copies: 1,
    };
    if expansion.traffic != expected_expansion {
        return Err(FusedCompactDomainProgramError::NonCanonicalTraffic);
    }
    validate_absorb_traffic(absorb.traffic, destination, columns, tail)?;
    let evaluation_and_tail = absorb
        .traffic
        .owned_read_bytes
        .checked_sub(destination_bytes)
        .ok_or(FusedCompactDomainProgramError::NonCanonicalTraffic)?;
    Ok(CommitProgramTraffic {
        // Source-major execution loads each compact source row once, then
        // writes every lifted-and-absorbed destination row directly.
        owned_read_bytes: source_bytes
            .checked_add(evaluation_and_tail)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: destination_bytes,
        kernel_launches: 1,
        device_copies: 0,
    })
}

pub(super) fn validate_finalize_traffic(
    traffic: CommitProgramTraffic,
    state: DomainCooperativeSlabSlice,
    tail: CompactDomainTail,
) -> Result<(), FusedCompactDomainProgramError> {
    let state_bytes = bytes(state.len_words)?;
    let tail_bytes = u64::try_from(state.len_words / HASH_WORDS)
        .ok()
        .and_then(|rows| rows.checked_mul(u64::from(tail.columns)))
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let expected = CommitProgramTraffic {
        owned_read_bytes: state_bytes
            .checked_add(tail_bytes)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: state_bytes,
        kernel_launches: 1,
        device_copies: 0,
    };
    if traffic != expected {
        return Err(FusedCompactDomainProgramError::NonCanonicalTraffic);
    }
    Ok(())
}

pub(super) fn validate_span(
    step: usize,
    state: DomainCooperativeSlabSlice,
    scratch: DomainCooperativeSlabSlice,
    capacity: usize,
) -> Result<(), FusedCompactDomainProgramError> {
    if end(state)? > capacity || end(scratch)? > capacity || !disjoint(state, scratch)? {
        return Err(FusedCompactDomainProgramError::SpanOverlap { step });
    }
    Ok(())
}

pub(super) fn validate_transition_spans(
    step: usize,
    source: DomainCooperativeSlabSlice,
    destination: DomainCooperativeSlabSlice,
    scratch: DomainCooperativeSlabSlice,
    capacity: usize,
) -> Result<(), FusedCompactDomainProgramError> {
    validate_span(step, source, scratch, capacity)?;
    validate_span(step, destination, scratch, capacity)?;
    if !disjoint(source, destination)? {
        return Err(FusedCompactDomainProgramError::SpanOverlap { step });
    }
    Ok(())
}

pub(super) fn receipt(
    qualified_slab_capacity_words: usize,
    compact_reduced_slab_words: usize,
    transitions: Vec<FusedCompactDomainTransition>,
    current_leaf_traffic: CommitProgramTraffic,
    fused_leaf_traffic: CommitProgramTraffic,
    current_leaf_compressions: u64,
    fused_leaf_compressions: u64,
) -> Result<FusedCompactDomainReceipt, FusedCompactDomainProgramError> {
    let current_expansion_kernel_launches = sum_u32(
        transitions
            .iter()
            .map(|transition| transition.expansion_bands),
    )?;
    let transition_count = u32::try_from(transitions.len())
        .map_err(|_| FusedCompactDomainProgramError::SizeOverflow)?;
    let current_expand_absorb_kernel_launches = current_expansion_kernel_launches
        .checked_add(transition_count)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    Ok(FusedCompactDomainReceipt {
        qualified_slab_capacity_words,
        compact_reduced_slab_words,
        fixed_scratch_words: PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        peak_transition_words: transitions
            .iter()
            .map(|transition| transition.peak_words)
            .max()
            .unwrap_or(0),
        current_leaf_traffic,
        fused_leaf_traffic,
        current_expansion_kernel_launches,
        current_expand_absorb_kernel_launches,
        fused_expand_absorb_kernel_launches: transition_count,
        kernel_launches_removed: sum_u32(
            transitions
                .iter()
                .map(|transition| transition.kernel_launches_removed),
        )?,
        device_copies_removed: sum_u32(
            transitions
                .iter()
                .map(|transition| transition.device_copies_removed),
        )?,
        expanded_state_write_bytes_removed: sum_u64(
            transitions
                .iter()
                .map(|transition| transition.expanded_state_write_bytes_removed),
        )?,
        expanded_state_reread_bytes_removed: sum_u64(
            transitions
                .iter()
                .map(|transition| transition.expanded_state_reread_bytes_removed),
        )?,
        expansion_scratch_read_bytes_removed: sum_u64(
            transitions
                .iter()
                .map(|transition| transition.expansion_scratch_read_bytes_removed),
        )?,
        expansion_scratch_write_bytes_removed: sum_u64(
            transitions
                .iter()
                .map(|transition| transition.expansion_scratch_write_bytes_removed),
        )?,
        current_leaf_compressions,
        fused_leaf_compressions,
        transitions,
    })
}

pub(super) fn canonical_tail(absorbed_columns: u32) -> Option<CompactDomainTail> {
    if absorbed_columns == 0 {
        return None;
    }
    let columns = (absorbed_columns - 1) % 16 + 1;
    Some(CompactDomainTail {
        first_column: absorbed_columns - columns,
        columns,
    })
}

fn block_boundaries(first: u32, end: u32) -> u32 {
    if first >= end {
        0
    } else {
        (end - 1) / 16 - first.saturating_sub(1) / 16
    }
}

pub(super) fn compact_state_words(log_size: u32) -> Result<usize, FusedCompactDomainProgramError> {
    1usize
        .checked_shl(log_size)
        .and_then(|rows| rows.checked_mul(HASH_WORDS))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

pub(super) fn row_count(log_size: u32) -> Result<u64, FusedCompactDomainProgramError> {
    1u64.checked_shl(log_size)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

pub(super) fn bytes(words: usize) -> Result<u64, FusedCompactDomainProgramError> {
    u64::try_from(words)
        .ok()
        .and_then(|words| words.checked_mul(WORD_BYTES))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

fn end(span: DomainCooperativeSlabSlice) -> Result<usize, FusedCompactDomainProgramError> {
    span.end_words()
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

pub(super) fn disjoint(
    left: DomainCooperativeSlabSlice,
    right: DomainCooperativeSlabSlice,
) -> Result<bool, FusedCompactDomainProgramError> {
    Ok(end(left)? <= right.offset_words || end(right)? <= left.offset_words)
}

pub(super) fn add_traffic(
    left: CommitProgramTraffic,
    right: CommitProgramTraffic,
) -> Result<CommitProgramTraffic, FusedCompactDomainProgramError> {
    Ok(CommitProgramTraffic {
        owned_read_bytes: left
            .owned_read_bytes
            .checked_add(right.owned_read_bytes)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: left
            .owned_write_bytes
            .checked_add(right.owned_write_bytes)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        kernel_launches: left
            .kernel_launches
            .checked_add(right.kernel_launches)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
        device_copies: left
            .device_copies
            .checked_add(right.device_copies)
            .ok_or(FusedCompactDomainProgramError::SizeOverflow)?,
    })
}

fn sum_u64(mut values: impl Iterator<Item = u64>) -> Result<u64, FusedCompactDomainProgramError> {
    values
        .try_fold(0u64, |sum, value| sum.checked_add(value))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

fn sum_u32(mut values: impl Iterator<Item = u32>) -> Result<u32, FusedCompactDomainProgramError> {
    values
        .try_fold(0u32, |sum, value| sum.checked_add(value))
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)
}

pub(super) fn cache_key(compact: u64, qualified_slab_words: usize) -> u64 {
    CACHE_TAG
        .iter()
        .chain(compact.to_le_bytes().iter())
        .chain(qualified_slab_words.to_le_bytes().iter())
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}
