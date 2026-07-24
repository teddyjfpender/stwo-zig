//! Address-free native-domain run-sum plan for one quotient-numerator group.
//!
//! The plan aggregates a contiguous lower-log prefix once on each source
//! domain, expands those sums in canonical run order, and leaves the
//! full-domain suffix direct. It owns no device address and cannot admit
//! scratch reuse without an explicit same-stream liveness proof.

use core::mem::size_of;

use blake3::Hasher;

use super::quotient_numerator_staged_single_write::QuotientNumeratorStagedSingleWritePlan;

const TERM_WORDS: usize = 3;
const IDENTITY_DOMAIN: &[u8] = b"stwo.quotient-numerator.run-sum.v1\0";

/// Fixed kernel-parameter capacity. The complete by-value manifest is 400 B.
pub const QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS: usize = 24;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QuotientNumeratorRunSumExpansionEntry {
    pub term_begin: u32,
    pub term_end: u32,
    pub source_log_size: u32,
    pub scratch_offset_words: u32,
}

impl QuotientNumeratorRunSumExpansionEntry {
    pub fn term_count(self) -> u32 {
        self.term_end - self.term_begin
    }

    pub fn scratch_len_words(self) -> usize {
        1usize << self.source_log_size
    }
}

/// Complete bounded expansion ABI. Inactive entries are all-zero.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorRunSumExpansionManifest {
    pub run_count: u32,
    pub direct_term_begin: u32,
    pub direct_term_end: u32,
    pub target_group_log_size: u32,
    pub entries: [QuotientNumeratorRunSumExpansionEntry; QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS],
}

impl QuotientNumeratorRunSumExpansionManifest {
    pub fn active_entries(&self) -> &[QuotientNumeratorRunSumExpansionEntry] {
        &self.entries[..self.run_count as usize]
    }
}

pub const QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES: usize =
    size_of::<QuotientNumeratorRunSumExpansionManifest>();
/// Manifest plus twelve 64-bit pointer arguments passed to the CUDA kernel.
pub const QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_KERNEL_PARAMETER_BYTES: usize =
    QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES + 12 * size_of::<usize>();
const _: () = assert!(QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES == 400);
const _: () = assert!(QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_KERNEL_PARAMETER_BYTES == 496);

/// Facts supplied by the prepared runtime's arena and capture authorities.
///
/// Every boolean is deliberately fail-closed. Coordinate capacities are the
/// actual bound slices, not merely the victim group's logical row count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorRunSumLiveness {
    pub same_stream_canonical_group_order: bool,
    pub external_destination_ids_unique: bool,
    pub victim_unread_before_own_producer: bool,
    pub victim_fully_overwritten_by_own_producer: bool,
    pub downstream_consumers_after_all_group_producers: bool,
    pub victim_coordinate_capacity_words: [usize; 4],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuotientNumeratorRunSumReceipt {
    pub target_group: usize,
    pub victim_group: usize,
    pub target_group_log_size: u32,
    pub victim_group_log_size: u32,
    pub target_term_begin: u32,
    pub target_term_end: u32,
    pub precomputed_term_count: u32,
    pub direct_term_count: u32,
    pub scratch_words_per_coordinate: usize,
    pub victim_coordinate_capacity_words: [usize; 4],
    pub margin_words_per_coordinate: [usize; 4],
    pub baseline_row_terms: u64,
    pub precompute_products: u64,
    pub direct_products: u64,
    pub candidate_products: u64,
    pub expansion_adds: u64,
    pub candidate_add_units: u64,
    pub products_saved: u64,
    pub add_units_saved: u64,
    pub expansion_manifest_bytes: usize,
    pub expansion_kernel_parameter_bytes: usize,
    pub manifest: QuotientNumeratorRunSumExpansionManifest,
    pub liveness: QuotientNumeratorRunSumLiveness,
    pub identity: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum QuotientNumeratorRunSumError {
    GroupOutOfBounds {
        group: usize,
        group_count: usize,
    },
    VictimNotLater {
        target_group: usize,
        victim_group: usize,
    },
    LivenessNotProven(&'static str),
    DescriptorInvariant(&'static str),
    UnsupportedAggregatedSourceLogZero,
    SingletonAggregatedRun {
        source_log_size: u32,
    },
    TooManyRuns {
        actual: usize,
        maximum: usize,
    },
    VictimCoordinateTooSmall {
        coordinate: usize,
        required_words: usize,
        available_words: usize,
    },
    SizeOverflow,
}

impl core::fmt::Display for QuotientNumeratorRunSumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid quotient-numerator run-sum plan: {self:?}")
    }
}

impl std::error::Error for QuotientNumeratorRunSumError {}

pub fn quotient_numerator_run_sum_plan(
    staged: &QuotientNumeratorStagedSingleWritePlan,
    target_group: usize,
    victim_group: usize,
    liveness: QuotientNumeratorRunSumLiveness,
) -> Result<QuotientNumeratorRunSumReceipt, QuotientNumeratorRunSumError> {
    let groups = &staged.requirements().groups;
    let target =
        groups
            .get(target_group)
            .ok_or(QuotientNumeratorRunSumError::GroupOutOfBounds {
                group: target_group,
                group_count: groups.len(),
            })?;
    let victim =
        groups
            .get(victim_group)
            .ok_or(QuotientNumeratorRunSumError::GroupOutOfBounds {
                group: victim_group,
                group_count: groups.len(),
            })?;
    if victim_group <= target_group {
        return Err(QuotientNumeratorRunSumError::VictimNotLater {
            target_group,
            victim_group,
        });
    }
    validate_liveness(liveness)?;

    let offsets = staged.group_offsets();
    let (&target_begin, &target_end) = offsets
        .get(target_group)
        .zip(offsets.get(target_group + 1))
        .ok_or(QuotientNumeratorRunSumError::DescriptorInvariant(
            "group offsets do not cover the target",
        ))?;
    if target_begin >= target_end {
        return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
            "target group is empty",
        ));
    }
    let descriptors = staged.term_descriptors();
    let begin_words = target_begin as usize * TERM_WORDS;
    let end_words = target_end as usize * TERM_WORDS;
    let target_descriptors = descriptors.get(begin_words..end_words).ok_or(
        QuotientNumeratorRunSumError::DescriptorInvariant(
            "target descriptor range is out of bounds",
        ),
    )?;

    let mut manifest = QuotientNumeratorRunSumExpansionManifest {
        run_count: 0,
        direct_term_begin: target_end,
        direct_term_end: target_end,
        target_group_log_size: target.log_size,
        entries: [QuotientNumeratorRunSumExpansionEntry::default();
            QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS],
    };
    let mut scratch_words = 0usize;
    let mut precompute_products = 0u64;
    let mut precomputed_terms = 0u32;
    let mut cursor = 0usize;
    let mut prior_log = None;
    while cursor < target_descriptors.len() / TERM_WORDS {
        let descriptor = &target_descriptors[cursor * TERM_WORDS..][..TERM_WORDS];
        let source_log = descriptor[2];
        if source_log > target.log_size {
            return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
                "source log exceeds target group log",
            ));
        }
        if prior_log.is_some_and(|prior| source_log < prior) {
            return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
                "source-log runs are not monotone",
            ));
        }
        let run_begin = cursor;
        cursor += 1;
        while cursor < target_descriptors.len() / TERM_WORDS
            && target_descriptors[cursor * TERM_WORDS + 2] == source_log
        {
            cursor += 1;
        }
        prior_log = Some(source_log);
        let absolute_begin = target_begin
            .checked_add(
                u32::try_from(run_begin).map_err(|_| QuotientNumeratorRunSumError::SizeOverflow)?,
            )
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
        let absolute_end = target_begin
            .checked_add(
                u32::try_from(cursor).map_err(|_| QuotientNumeratorRunSumError::SizeOverflow)?,
            )
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
        if source_log == target.log_size {
            manifest.direct_term_begin = absolute_begin;
            manifest.direct_term_end = absolute_end;
            if cursor != target_descriptors.len() / TERM_WORDS {
                return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
                    "full-domain direct terms are not one terminal suffix",
                ));
            }
            break;
        }
        // The lift mapping addresses two parity rows at log zero, while a
        // native 2^0 scratch image owns only one word.
        if source_log == 0 {
            return Err(QuotientNumeratorRunSumError::UnsupportedAggregatedSourceLogZero);
        }
        let term_count = absolute_end - absolute_begin;
        if term_count <= 1 {
            return Err(QuotientNumeratorRunSumError::SingletonAggregatedRun {
                source_log_size: source_log,
            });
        }
        let run_index = manifest.run_count as usize;
        if run_index == QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS {
            return Err(QuotientNumeratorRunSumError::TooManyRuns {
                actual: run_index + 1,
                maximum: QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS,
            });
        }
        let run_words = 1usize
            .checked_shl(source_log)
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
        manifest.entries[run_index] = QuotientNumeratorRunSumExpansionEntry {
            term_begin: absolute_begin,
            term_end: absolute_end,
            source_log_size: source_log,
            scratch_offset_words: u32::try_from(scratch_words)
                .map_err(|_| QuotientNumeratorRunSumError::SizeOverflow)?,
        };
        manifest.run_count += 1;
        scratch_words = scratch_words
            .checked_add(run_words)
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
        precomputed_terms = precomputed_terms
            .checked_add(term_count)
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
        precompute_products = precompute_products
            .checked_add(u64::from(term_count) * run_words as u64)
            .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    }
    if manifest.run_count == 0 {
        return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
            "target has no reusable lower-log run",
        ));
    }
    if manifest.direct_term_begin == manifest.direct_term_end {
        return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
            "target has no nonempty terminal full-domain direct suffix",
        ));
    }
    if manifest.direct_term_end != target_end {
        return Err(QuotientNumeratorRunSumError::DescriptorInvariant(
            "direct suffix does not reach the target end",
        ));
    }

    let mut margins = [0usize; 4];
    for (coordinate, (&available, margin)) in liveness
        .victim_coordinate_capacity_words
        .iter()
        .zip(&mut margins)
        .enumerate()
    {
        if available < scratch_words {
            return Err(QuotientNumeratorRunSumError::VictimCoordinateTooSmall {
                coordinate,
                required_words: scratch_words,
                available_words: available,
            });
        }
        *margin = available - scratch_words;
    }

    let target_rows = 1u64
        .checked_shl(target.log_size)
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let target_terms = target_end - target_begin;
    let direct_terms = manifest.direct_term_end - manifest.direct_term_begin;
    let baseline_row_terms = target_rows
        .checked_mul(u64::from(target_terms))
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let direct_products = target_rows
        .checked_mul(u64::from(direct_terms))
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let candidate_products = precompute_products
        .checked_add(direct_products)
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let expansion_adds = target_rows
        .checked_mul(u64::from(manifest.run_count))
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let candidate_add_units = candidate_products
        .checked_add(expansion_adds)
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let products_saved = baseline_row_terms
        .checked_sub(candidate_products)
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;
    let add_units_saved = baseline_row_terms
        .checked_sub(candidate_add_units)
        .ok_or(QuotientNumeratorRunSumError::SizeOverflow)?;

    let mut receipt = QuotientNumeratorRunSumReceipt {
        target_group,
        victim_group,
        target_group_log_size: target.log_size,
        victim_group_log_size: victim.log_size,
        target_term_begin: target_begin,
        target_term_end: target_end,
        precomputed_term_count: precomputed_terms,
        direct_term_count: direct_terms,
        scratch_words_per_coordinate: scratch_words,
        victim_coordinate_capacity_words: liveness.victim_coordinate_capacity_words,
        margin_words_per_coordinate: margins,
        baseline_row_terms,
        precompute_products,
        direct_products,
        candidate_products,
        expansion_adds,
        candidate_add_units,
        products_saved,
        add_units_saved,
        expansion_manifest_bytes: QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES,
        expansion_kernel_parameter_bytes:
            QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_KERNEL_PARAMETER_BYTES,
        manifest,
        liveness,
        identity: [0; 32],
    };
    receipt.identity = receipt_identity(&receipt, target_descriptors)?;
    Ok(receipt)
}

fn validate_liveness(
    liveness: QuotientNumeratorRunSumLiveness,
) -> Result<(), QuotientNumeratorRunSumError> {
    for (proven, label) in [
        (
            liveness.same_stream_canonical_group_order,
            "same-stream canonical group order is unproven",
        ),
        (
            liveness.external_destination_ids_unique,
            "external destination uniqueness is unproven",
        ),
        (
            liveness.victim_unread_before_own_producer,
            "victim has an unexcluded pre-producer reader",
        ),
        (
            liveness.victim_fully_overwritten_by_own_producer,
            "victim full overwrite by its own producer is unproven",
        ),
        (
            liveness.downstream_consumers_after_all_group_producers,
            "downstream ordering after group producers is unproven",
        ),
    ] {
        if !proven {
            return Err(QuotientNumeratorRunSumError::LivenessNotProven(label));
        }
    }
    Ok(())
}

fn receipt_identity(
    receipt: &QuotientNumeratorRunSumReceipt,
    target_descriptors: &[u32],
) -> Result<[u8; 32], QuotientNumeratorRunSumError> {
    let mut hash = Hasher::new();
    hash.update(IDENTITY_DOMAIN);
    hash_usize(&mut hash, QUOTIENT_NUMERATOR_RUN_SUM_MAX_RUNS)?;
    hash_usize(
        &mut hash,
        QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_MANIFEST_BYTES,
    )?;
    hash_usize(
        &mut hash,
        QUOTIENT_NUMERATOR_RUN_SUM_EXPANSION_KERNEL_PARAMETER_BYTES,
    )?;
    hash_usize(&mut hash, receipt.target_group)?;
    hash_usize(&mut hash, receipt.victim_group)?;
    hash.update(&receipt.target_group_log_size.to_le_bytes());
    hash.update(&receipt.victim_group_log_size.to_le_bytes());
    hash.update(&receipt.target_term_begin.to_le_bytes());
    hash.update(&receipt.target_term_end.to_le_bytes());
    for word in target_descriptors {
        hash.update(&word.to_le_bytes());
    }
    hash.update(&receipt.manifest.run_count.to_le_bytes());
    hash.update(&receipt.manifest.direct_term_begin.to_le_bytes());
    hash.update(&receipt.manifest.direct_term_end.to_le_bytes());
    for entry in receipt.manifest.active_entries() {
        hash.update(&entry.term_begin.to_le_bytes());
        hash.update(&entry.term_end.to_le_bytes());
        hash.update(&entry.source_log_size.to_le_bytes());
        hash.update(&entry.scratch_offset_words.to_le_bytes());
    }
    hash_usize(&mut hash, receipt.scratch_words_per_coordinate)?;
    for capacity in receipt.victim_coordinate_capacity_words {
        hash_usize(&mut hash, capacity)?;
    }
    hash.update(&[
        u8::from(receipt.liveness.same_stream_canonical_group_order),
        u8::from(receipt.liveness.external_destination_ids_unique),
        u8::from(receipt.liveness.victim_unread_before_own_producer),
        u8::from(receipt.liveness.victim_fully_overwritten_by_own_producer),
        u8::from(
            receipt
                .liveness
                .downstream_consumers_after_all_group_producers,
        ),
    ]);
    for value in [
        receipt.baseline_row_terms,
        receipt.precompute_products,
        receipt.direct_products,
        receipt.candidate_products,
        receipt.expansion_adds,
        receipt.candidate_add_units,
    ] {
        hash.update(&value.to_le_bytes());
    }
    Ok(*hash.finalize().as_bytes())
}

fn hash_usize(hash: &mut Hasher, value: usize) -> Result<(), QuotientNumeratorRunSumError> {
    hash.update(
        &u64::try_from(value)
            .map_err(|_| QuotientNumeratorRunSumError::SizeOverflow)?
            .to_le_bytes(),
    );
    Ok(())
}

#[cfg(test)]
#[path = "quotient_numerator_run_sum_tests.rs"]
mod tests;
