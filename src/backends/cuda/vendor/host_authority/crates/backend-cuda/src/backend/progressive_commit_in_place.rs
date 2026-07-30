//! Pure launch planning for the single-slab progressive commitment lane.
//!
//! Every destructive CUDA launch is represented here first. A band may read
//! and write the same allocation, but its byte ranges never overlap. Ordered
//! bands only overwrite source rows consumed by earlier launches. The first
//! source row/pair is saved in a 192-byte tail before destructive work begins.

use std::ops::Range;

use stwo::core::vcs::blake2_hash::Blake2sHash;
#[cfg(test)]
use stwo::core::vcs::blake2_hash::Blake2sHasherGeneric;

use super::progressive_commit::PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;

const HASH_BYTES: usize = core::mem::size_of::<Blake2sHash>();
const SAVED_EXPANSION_STATES: usize = 2;
pub const PROGRESSIVE_IN_PLACE_SCRATCH_BYTES: usize =
    SAVED_EXPANSION_STATES * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;
pub const PROGRESSIVE_IN_PLACE_SCRATCH_WORDS: usize =
    PROGRESSIVE_IN_PLACE_SCRATCH_BYTES / core::mem::size_of::<u32>();
const IN_PLACE_CACHE_TAG: &[u8] = b"progressive-commit-in-place-slab-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InPlaceBand {
    pub first: usize,
    pub count: usize,
    pub read: Range<usize>,
    pub write: Range<usize>,
    pub reads_scratch: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InPlaceBandPlan {
    pub main_bytes: usize,
    pub scratch: Range<usize>,
    pub save: (Range<usize>, Range<usize>),
    pub bands: Vec<InPlaceBand>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InPlacePlanError {
    InvalidLogRange,
    InvalidPowerOfTwo,
    SizeOverflow,
}

pub fn progressive_in_place_slab_words(lifting_log_size: u32) -> Result<usize, InPlacePlanError> {
    state_rows(lifting_log_size)?
        .checked_mul(PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES / core::mem::size_of::<u32>())
        .and_then(|words| words.checked_add(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS))
        .ok_or(InPlacePlanError::SizeOverflow)
}

pub fn progressive_in_place_cache_key(base: u64) -> u64 {
    IN_PLACE_CACHE_TAG
        .iter()
        .chain(base.to_le_bytes().iter())
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
        })
}

/// High-to-low source-pair bands for one state-domain expansion.
pub fn expansion_band_plan(
    from_log: u32,
    to_log: u32,
    capacity_log: u32,
) -> Result<InPlaceBandPlan, InPlacePlanError> {
    if from_log == 0 || from_log >= to_log || to_log > capacity_log || capacity_log >= 31 {
        return Err(InPlacePlanError::InvalidLogRange);
    }
    let from_rows = state_rows(from_log)?;
    let to_rows = state_rows(to_log)?;
    let capacity_rows = state_rows(capacity_log)?;
    let expansion = 1usize
        .checked_shl(to_log - from_log)
        .ok_or(InPlacePlanError::SizeOverflow)?;
    let main_bytes = bytes(capacity_rows, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)?;
    let scratch = main_bytes..main_bytes + PROGRESSIVE_IN_PLACE_SCRATCH_BYTES;
    let save_bytes = SAVED_EXPANSION_STATES * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;
    let save = (0..save_bytes, scratch.start..scratch.start + save_bytes);

    let mut bands = Vec::new();
    let mut pair_end = from_rows / 2;
    while pair_end > 1 {
        let pair_begin = pair_end.div_ceil(expansion);
        bands.push(expansion_band(pair_begin, pair_end, expansion, false)?);
        pair_end = pair_begin;
    }
    bands.push(InPlaceBand {
        first: 0,
        count: 1,
        read: scratch.clone(),
        write: 0..bytes(2 * expansion, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)?,
        reads_scratch: true,
    });
    debug_assert_eq!(
        bands.iter().map(|band| band.write.len()).sum::<usize>(),
        bytes(to_rows, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES).unwrap()
    );
    Ok(InPlaceBandPlan {
        main_bytes,
        scratch,
        save,
        bands,
    })
}

/// Low-to-high state-to-hash compaction bands.
pub fn finalize_band_plan(rows: usize) -> Result<InPlaceBandPlan, InPlacePlanError> {
    require_power_of_two(rows)?;
    let main_bytes = bytes(rows, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES)?;
    let scratch = main_bytes..main_bytes + PROGRESSIVE_IN_PLACE_SCRATCH_BYTES;
    let save = (
        0..PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
        scratch.start..scratch.start + PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES,
    );
    let mut bands = compaction_bands(rows, PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES, HASH_BYTES)?;
    bands.push(InPlaceBand {
        first: 0,
        count: 1,
        read: save.1.clone(),
        write: 0..HASH_BYTES,
        reads_scratch: true,
    });
    Ok(InPlaceBandPlan {
        main_bytes,
        scratch,
        save,
        bands,
    })
}

/// Low-to-high parent compaction bands for one column-free Merkle level.
pub fn merkle_band_plan(
    output_hashes: usize,
    slab_main_bytes: usize,
) -> Result<InPlaceBandPlan, InPlacePlanError> {
    require_power_of_two(output_hashes)?;
    let scratch = slab_main_bytes..slab_main_bytes + PROGRESSIVE_IN_PLACE_SCRATCH_BYTES;
    let saved_children_bytes = 2 * HASH_BYTES;
    let save = (
        0..saved_children_bytes,
        scratch.start..scratch.start + saved_children_bytes,
    );
    let mut bands = compaction_bands(output_hashes, 2 * HASH_BYTES, HASH_BYTES)?;
    bands.push(InPlaceBand {
        first: 0,
        count: 1,
        read: save.1.clone(),
        write: 0..HASH_BYTES,
        reads_scratch: true,
    });
    Ok(InPlaceBandPlan {
        main_bytes: slab_main_bytes,
        scratch,
        save,
        bands,
    })
}

#[cfg(test)]
pub fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

fn expansion_band(
    pair_begin: usize,
    pair_end: usize,
    expansion: usize,
    reads_scratch: bool,
) -> Result<InPlaceBand, InPlacePlanError> {
    let state_bytes = PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;
    Ok(InPlaceBand {
        first: pair_begin,
        count: pair_end - pair_begin,
        read: bytes(2 * pair_begin, state_bytes)?..bytes(2 * pair_end, state_bytes)?,
        write: bytes(2 * expansion * pair_begin, state_bytes)?
            ..bytes(2 * expansion * pair_end, state_bytes)?,
        reads_scratch,
    })
}

fn compaction_bands(
    rows: usize,
    input_stride: usize,
    output_stride: usize,
) -> Result<Vec<InPlaceBand>, InPlacePlanError> {
    let ratio = input_stride / output_stride;
    debug_assert_eq!(input_stride % output_stride, 0);
    let mut bands = Vec::new();
    let mut first = 1usize;
    while first < rows {
        let end = rows.min(
            first
                .checked_mul(ratio)
                .ok_or(InPlacePlanError::SizeOverflow)?,
        );
        bands.push(InPlaceBand {
            first,
            count: end - first,
            read: bytes(first, input_stride)?..bytes(end, input_stride)?,
            write: bytes(first, output_stride)?..bytes(end, output_stride)?,
            reads_scratch: false,
        });
        first = end;
    }
    Ok(bands)
}

fn state_rows(log: u32) -> Result<usize, InPlacePlanError> {
    1usize
        .checked_shl(log)
        .ok_or(InPlacePlanError::SizeOverflow)
}

fn bytes(count: usize, stride: usize) -> Result<usize, InPlacePlanError> {
    count
        .checked_mul(stride)
        .ok_or(InPlacePlanError::SizeOverflow)
}

fn require_power_of_two(value: usize) -> Result<(), InPlacePlanError> {
    if value != 0 && value.is_power_of_two() {
        Ok(())
    } else {
        Err(InPlacePlanError::InvalidPowerOfTwo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::progressive_commit::{lifted_column_index, merkle_root};

    fn assert_safe(plan: &InPlaceBandPlan) {
        assert!(!ranges_overlap(&plan.save.0, &plan.save.1));
        for band in &plan.bands {
            assert!(!ranges_overlap(&band.read, &band.write), "{band:?}");
            assert!(band.read.end <= plan.scratch.end);
            assert!(band.write.end <= plan.main_bytes);
        }
        let main = plan
            .bands
            .iter()
            .filter(|band| !band.reads_scratch)
            .collect::<Vec<_>>();
        for (index, band) in main.iter().enumerate() {
            for later in &main[index + 1..] {
                assert!(
                    !ranges_overlap(&band.write, &later.read),
                    "earlier write destroys a future read: {band:?} -> {later:?}"
                );
            }
        }
    }

    #[test]
    fn every_small_expansion_band_is_disjoint_ordered_and_exact() {
        for capacity_log in 2..=12 {
            for from_log in 1..capacity_log {
                for to_log in from_log + 1..=capacity_log {
                    let plan = expansion_band_plan(from_log, to_log, capacity_log).unwrap();
                    assert_safe(&plan);
                    let output_bytes = (1usize << to_log) * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES;
                    assert_eq!(
                        plan.bands
                            .iter()
                            .map(|band| band.write.len())
                            .sum::<usize>(),
                        output_bytes
                    );
                }
            }
        }
    }

    #[test]
    fn in_place_expansion_matches_lifted_index_for_all_small_lifts() {
        for from_log in 1..=9 {
            for to_log in from_log + 1..=10 {
                let before = (0..1usize << from_log).collect::<Vec<_>>();
                let expected = (0..1usize << to_log)
                    .map(|row| before[lifted_column_index(row, from_log, to_log)])
                    .collect::<Vec<_>>();
                let actual = expand_tokens(before, from_log, to_log);
                assert_eq!(actual, expected, "{from_log}->{to_log}");
            }
        }
    }

    #[test]
    fn finalize_and_merkle_bands_cover_every_output_without_future_clobber() {
        for log in 1..=16 {
            let rows = 1usize << log;
            let finalize = finalize_band_plan(rows).unwrap();
            assert_safe(&finalize);
            assert_eq!(
                finalize.bands.iter().map(|band| band.count).sum::<usize>(),
                rows
            );
            let merkle = merkle_band_plan(rows / 2, finalize.main_bytes).unwrap();
            assert_safe(&merkle);
            assert_eq!(
                merkle.bands.iter().map(|band| band.count).sum::<usize>(),
                rows / 2
            );
        }
    }

    #[test]
    fn randomized_power_of_two_roots_match_out_of_place_reference() {
        let mut seed = 0x9e37_79b9u32;
        for log in 1..=12 {
            let leaves = (0..1usize << log)
                .map(|_| {
                    let mut bytes = [0u8; 32];
                    for chunk in bytes.chunks_exact_mut(4) {
                        seed ^= seed << 13;
                        seed ^= seed >> 17;
                        seed ^= seed << 5;
                        chunk.copy_from_slice(&seed.to_le_bytes());
                    }
                    Blake2sHasherGeneric::<false>::hash(&bytes)
                })
                .collect::<Vec<_>>();
            assert_eq!(in_place_root(leaves.clone()), merkle_root(leaves));
        }
    }

    #[test]
    fn in_place_storage_has_a_distinct_stable_cache_identity() {
        assert_ne!(progressive_in_place_cache_key(7), 7);
        assert_eq!(
            progressive_in_place_cache_key(7),
            progressive_in_place_cache_key(7)
        );
        assert_ne!(
            progressive_in_place_cache_key(7),
            progressive_in_place_cache_key(8)
        );
    }

    fn expand_tokens(mut states: Vec<usize>, from_log: u32, to_log: u32) -> Vec<usize> {
        let from_rows = 1usize << from_log;
        let to_rows = 1usize << to_log;
        states.resize(to_rows, usize::MAX);
        let saved = [states[0], states[1]];
        let expansion = 1usize << (to_log - from_log);
        let plan = expansion_band_plan(from_log, to_log, to_log).unwrap();
        for band in plan.bands {
            for local in 0..band.count {
                let pair = band.first + local;
                let pair_states = if band.reads_scratch {
                    saved
                } else {
                    [states[2 * pair], states[2 * pair + 1]]
                };
                let base = 2 * expansion * pair;
                for child in 0..expansion {
                    states[base + 2 * child] = pair_states[0];
                    states[base + 2 * child + 1] = pair_states[1];
                }
            }
        }
        states.truncate(to_rows.max(from_rows));
        states
    }

    fn in_place_root(mut layer: Vec<Blake2sHash>) -> Blake2sHash {
        while layer.len() > 1 {
            let outputs = layer.len() / 2;
            let saved = [layer[0], layer[1]];
            let plan = merkle_band_plan(outputs, layer.len() * HASH_BYTES).unwrap();
            for band in plan.bands {
                for local in 0..band.count {
                    let output = band.first + local;
                    let children = if band.reads_scratch {
                        saved
                    } else {
                        [layer[2 * output], layer[2 * output + 1]]
                    };
                    layer[output] =
                        Blake2sHasherGeneric::<false>::concat_and_hash(&children[0], &children[1]);
                }
            }
            layer.truncate(outputs);
        }
        layer[0]
    }
}
