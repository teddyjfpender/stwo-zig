//! Canonical launch and destination-range derivation.

use super::*;

pub(super) fn canonical_launch(
    row_count: u32,
    mode: WitnessFeedLaunchMode,
) -> Result<WitnessFeedKernelLaunch, WitnessFeedAuthorityError> {
    if row_count == 0 {
        return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
    }
    Ok(WitnessFeedKernelLaunch {
        grid: [ceil_div(row_count, BLOCK_THREADS), 1, 1],
        block: [BLOCK_THREADS, 1, 1],
        static_shared_bytes: match mode {
            WitnessFeedLaunchMode::GlobalAtomics => 0,
            WitnessFeedLaunchMode::Privatized => u32_value(WITNESS_FEED_PRIVATIZED_SHARED_BYTES)?,
        },
        dynamic_shared_bytes: 0,
        cooperative: false,
        cluster: None,
        mode,
    })
}

pub(super) fn destination_effects(
    descriptors: &[u32],
    requirements: &WitnessFeedWorkspaceRequirements,
) -> Result<Vec<WitnessFeedDestinationEffect>, WitnessFeedAuthorityError> {
    let mut ranges = vec![Vec::new(); requirements.multiplicity_words.len()];
    for descriptor in descriptors.chunks_exact(WITNESS_FEED_DESCRIPTOR_WORDS) {
        let relation = descriptor[7] as usize;
        let table_words = descriptor[8] as usize;
        match WitnessFeedDescriptorKind::from_raw(descriptor[11])? {
            WitnessFeedDescriptorKind::MemoryIdDecode => {
                push_destination_range(
                    &mut ranges,
                    &requirements.multiplicity_words,
                    descriptor[10] as usize,
                    relation,
                    table_words,
                )?;
                push_destination_range(
                    &mut ranges,
                    &requirements.multiplicity_words,
                    descriptor[13] as usize,
                    relation,
                    descriptor[12] as usize,
                )?;
            }
            WitnessFeedDescriptorKind::Xor12 => {
                let len_words = table_words
                    .checked_mul(16)
                    .ok_or(WitnessFeedAuthorityError::SizeOverflow)?;
                push_exact_range(
                    &mut ranges,
                    &requirements.multiplicity_words,
                    descriptor[10] as usize,
                    WitnessFeedDestinationRange {
                        start_words: 0,
                        len_words,
                    },
                )?;
            }
            WitnessFeedDescriptorKind::Fold | WitnessFeedDescriptorKind::DependentXor => {
                push_destination_range(
                    &mut ranges,
                    &requirements.multiplicity_words,
                    descriptor[10] as usize,
                    relation,
                    table_words,
                )?;
            }
        }
    }
    ranges
        .into_iter()
        .zip(&requirements.multiplicity_words)
        .enumerate()
        .map(|(ordinal, (ranges, &atomic_len_words))| {
            let may_write_ranges = merge_ranges(ranges)?;
            if !canonical_ranges(&may_write_ranges, atomic_len_words) {
                return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
            }
            Ok(WitnessFeedDestinationEffect {
                destination_ordinal: u32_value(ordinal)?,
                atomic_start_words: 0,
                atomic_len_words,
                may_write_ranges,
            })
        })
        .collect()
}

fn push_destination_range(
    ranges: &mut [Vec<WitnessFeedDestinationRange>],
    destination_words: &[usize],
    destination: usize,
    relation: usize,
    table_words: usize,
) -> Result<(), WitnessFeedAuthorityError> {
    let start_words = relation
        .checked_mul(table_words)
        .ok_or(WitnessFeedAuthorityError::SizeOverflow)?;
    push_exact_range(
        ranges,
        destination_words,
        destination,
        WitnessFeedDestinationRange {
            start_words,
            len_words: table_words,
        },
    )
}

fn push_exact_range(
    ranges: &mut [Vec<WitnessFeedDestinationRange>],
    destination_words: &[usize],
    destination: usize,
    range: WitnessFeedDestinationRange,
) -> Result<(), WitnessFeedAuthorityError> {
    let words = destination_words
        .get(destination)
        .ok_or(WitnessFeedAuthorityError::InvalidCanonicalRequirements)?;
    let destination_ranges = ranges
        .get_mut(destination)
        .ok_or(WitnessFeedAuthorityError::InvalidCanonicalRequirements)?;
    if range.len_words == 0 || range.end_words()? > *words {
        return Err(WitnessFeedAuthorityError::InvalidCanonicalRequirements);
    }
    destination_ranges.push(range);
    Ok(())
}

fn merge_ranges(
    mut ranges: Vec<WitnessFeedDestinationRange>,
) -> Result<Vec<WitnessFeedDestinationRange>, WitnessFeedAuthorityError> {
    ranges.sort_unstable();
    let mut merged: Vec<WitnessFeedDestinationRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        let range_end = range.end_words()?;
        if let Some(last) = merged.last_mut() {
            let last_end = last.end_words()?;
            if range.start_words <= last_end {
                last.len_words = last_end.max(range_end) - last.start_words;
                continue;
            }
        }
        merged.push(range);
    }
    Ok(merged)
}

pub(super) fn canonical_ranges(
    ranges: &[WitnessFeedDestinationRange],
    destination_words: usize,
) -> bool {
    !ranges.is_empty()
        && ranges.iter().all(|range| {
            range.len_words > 0
                && range
                    .start_words
                    .checked_add(range.len_words)
                    .is_some_and(|end| end <= destination_words)
        })
        && ranges.windows(2).all(|pair| {
            pair[0]
                .start_words
                .checked_add(pair[0].len_words)
                .is_some_and(|end| end < pair[1].start_words)
        })
}

const fn ceil_div(value: u32, divisor: u32) -> u32 {
    1 + (value - 1) / divisor
}
