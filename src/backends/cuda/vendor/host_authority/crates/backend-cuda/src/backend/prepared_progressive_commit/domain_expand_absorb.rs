//! Pure compact-state expansion/absorb fusion program.
//!
//! Each compact h8 expansion is paired with its immediately following domain
//! absorb. The fused operation reads the old state once, reconstructs the
//! canonical lazy tail, absorbs the next batch, and writes the new state once.
//! Source and destination occupy disjoint ping/pong spans in the already-owned
//! qualified one-slab allocation. No native binding selects this model yet.

use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

mod accounting;
#[cfg(test)]
use accounting::disjoint;
use accounting::{
    add_traffic, bytes, cache_key, canonical_tail, compact_state_words, fused_transition_traffic,
    receipt, row_count, validate_absorb, validate_absorb_traffic, validate_finalize_traffic,
    validate_span, validate_transition_spans,
};

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / core::mem::size_of::<u32>();
const HASH_BYTES: u64 = core::mem::size_of::<Blake2sHash>() as u64;
const COMPACT_EXPANSION_SCRATCH_HASHES: u64 = 2;
const CACHE_TAG: &[u8] = b"stwo-compact-expand-absorb-ping-pong-v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FusedCompactDomainOperation {
    LdeBatch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        log_size: u32,
    },
    AbsorbDomainBatch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        log_size: u32,
        absorbed_columns_before: u32,
        initializes_state: bool,
        reconstructed_tail: Option<CompactDomainTail>,
        state: DomainCooperativeSlabSlice,
        leaf_compressions: u64,
    },
    ExpandAbsorbDomainBatch {
        batch_index: u32,
        first_column: u32,
        columns: u32,
        from_log_size: u32,
        to_log_size: u32,
        absorbed_columns_before: u32,
        expansion_bands: u32,
        reconstructed_tail: CompactDomainTail,
        source_state: DomainCooperativeSlabSlice,
        destination_state: DomainCooperativeSlabSlice,
        scratch: DomainCooperativeSlabSlice,
        leaf_compressions: u64,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        reconstructed_tail: CompactDomainTail,
        state: DomainCooperativeSlabSlice,
        leaf_compressions: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusedCompactDomainStep {
    pub operation: FusedCompactDomainOperation,
    pub traffic: CommitProgramTraffic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FusedCompactDomainTransition {
    pub batch_index: u32,
    pub from_log_size: u32,
    pub to_log_size: u32,
    pub expansion_bands: u32,
    pub source_state: DomainCooperativeSlabSlice,
    pub destination_state: DomainCooperativeSlabSlice,
    pub scratch: DomainCooperativeSlabSlice,
    /// Exact simultaneously-live words, excluding unused holes in the slab.
    pub peak_words: usize,
    pub qualified_slab_capacity_words: usize,
    pub current_traffic: CommitProgramTraffic,
    pub fused_traffic: CommitProgramTraffic,
    pub expanded_state_write_bytes_removed: u64,
    pub expanded_state_reread_bytes_removed: u64,
    pub expansion_scratch_read_bytes_removed: u64,
    pub expansion_scratch_write_bytes_removed: u64,
    pub kernel_launches_removed: u32,
    pub device_copies_removed: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusedCompactDomainReceipt {
    /// Capacity of the existing qualified 96-byte-state one-slab allocation.
    pub qualified_slab_capacity_words: usize,
    /// The reduced h8-only allocation reported by `CompactDomainProgram`.
    /// Fusion intentionally does not claim that smaller admission yet.
    pub compact_reduced_slab_words: usize,
    pub fixed_scratch_words: usize,
    pub peak_transition_words: usize,
    pub transitions: Vec<FusedCompactDomainTransition>,
    pub current_leaf_traffic: CommitProgramTraffic,
    pub fused_leaf_traffic: CommitProgramTraffic,
    pub current_expansion_kernel_launches: u32,
    pub current_expand_absorb_kernel_launches: u32,
    pub fused_expand_absorb_kernel_launches: u32,
    pub kernel_launches_removed: u32,
    pub device_copies_removed: u32,
    pub expanded_state_write_bytes_removed: u64,
    pub expanded_state_reread_bytes_removed: u64,
    pub expansion_scratch_read_bytes_removed: u64,
    pub expansion_scratch_write_bytes_removed: u64,
    pub current_leaf_compressions: u64,
    pub fused_leaf_compressions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FusedCompactDomainProgram {
    cache_key: u64,
    steps: Vec<FusedCompactDomainStep>,
    merkle_suffix: Vec<CommitProgramStep>,
    receipt: FusedCompactDomainReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FusedCompactDomainProgramError {
    Base(CommitProgramError),
    Compact(CompactDomainProgramError),
    NonCanonicalProgram,
    NonCanonicalBatch,
    NonCanonicalTail,
    NonCanonicalTraffic,
    InvalidState,
    MissingFinalize,
    ExpansionNotFollowedByAbsorb {
        step: usize,
    },
    ExpansionAbsorbMismatch {
        step: usize,
    },
    SlabCapacity {
        step: usize,
        required_words: usize,
        available_words: usize,
    },
    SpanOverlap {
        step: usize,
    },
    CompressionMismatch {
        current: u64,
        fused: u64,
    },
    SizeOverflow,
}

impl core::fmt::Display for FusedCompactDomainProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid fused compact-domain program: {self:?}")
    }
}

impl std::error::Error for FusedCompactDomainProgramError {}

impl From<CommitProgramError> for FusedCompactDomainProgramError {
    fn from(value: CommitProgramError) -> Self {
        Self::Base(value)
    }
}

impl From<CompactDomainProgramError> for FusedCompactDomainProgramError {
    fn from(value: CompactDomainProgramError) -> Self {
        Self::Compact(value)
    }
}

impl FusedCompactDomainProgram {
    /// Compile the dormant address-free successor. This validates all source
    /// programs but neither allocates memory nor selects a native launch.
    pub fn compile(
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
    ) -> Result<Self, FusedCompactDomainProgramError> {
        compact.validate_against(base, domain)?;
        let program = Self::compile_canonical(compact, domain.slab_words())?;
        program.validate_against(base, domain, compact)?;
        Ok(program)
    }

    pub fn validate_against(
        &self,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
    ) -> Result<(), FusedCompactDomainProgramError> {
        compact.validate_against(base, domain)?;
        if *self == Self::compile_canonical(compact, domain.slab_words())? {
            Ok(())
        } else {
            Err(FusedCompactDomainProgramError::NonCanonicalProgram)
        }
    }

    /// Canonical expected bytes for this sealed shape. The base oracle already
    /// cross-checks progressive leaves against full lifting independently.
    pub fn oracle(
        &self,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
        evaluations: &[Vec<u32>],
    ) -> Result<CommitProgramOracle, FusedCompactDomainProgramError> {
        self.validate_against(base, domain, compact)?;
        Ok(base.oracle(evaluations)?)
    }

    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub fn steps(&self) -> &[FusedCompactDomainStep] {
        &self.steps
    }

    pub fn merkle_suffix(&self) -> &[CommitProgramStep] {
        &self.merkle_suffix
    }

    pub fn receipt(&self) -> &FusedCompactDomainReceipt {
        &self.receipt
    }

    fn compile_canonical(
        compact: &CompactDomainProgram,
        qualified_slab_words: usize,
    ) -> Result<Self, FusedCompactDomainProgramError> {
        compile_steps(
            compact.cache_key(),
            compact.steps(),
            compact.merkle_suffix(),
            compact.comparison(),
            qualified_slab_words,
            compact.slab_words(),
        )
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Batch {
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
}

fn compile_steps(
    compact_cache_key: u64,
    compact_steps: &[CompactDomainStep],
    merkle_suffix: &[CommitProgramStep],
    current: CompactDomainComparison,
    qualified_slab_words: usize,
    compact_slab_words: usize,
) -> Result<FusedCompactDomainProgram, FusedCompactDomainProgramError> {
    if qualified_slab_words != current.current_state_slab_words
        || compact_slab_words != current.replacement_state_slab_words
    {
        return Err(FusedCompactDomainProgramError::NonCanonicalProgram);
    }
    let state_capacity_words = qualified_slab_words
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
    let scratch = DomainCooperativeSlabSlice {
        offset_words: state_capacity_words,
        len_words: PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
    };
    let transition_count = compact_steps
        .iter()
        .filter(|step| {
            matches!(
                step.operation,
                CompactDomainOperation::StateExpandInPlace { .. }
            )
        })
        .count();
    // Final compact hashes are the Merkle leaf layer at slab offset zero. Start
    // on the opposite side for an odd number of transitions so alternating
    // disjoint destinations end at zero without an unaccounted copy.
    let initial_state_is_high = transition_count % 2 == 1;

    let mut batches = Vec::new();
    let mut expected_first_column = 0u32;
    let mut state_started = false;
    for step in compact_steps {
        if let CompactDomainOperation::LdeBatch {
            batch_index,
            first_column,
            columns,
            log_size,
        } = step.operation
        {
            if state_started
                || columns == 0
                || batch_index as usize != batches.len()
                || first_column != expected_first_column
            {
                return Err(FusedCompactDomainProgramError::NonCanonicalBatch);
            }
            expected_first_column = expected_first_column
                .checked_add(columns)
                .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
            batches.push(Batch {
                batch_index,
                first_column,
                columns,
                log_size,
            });
        } else {
            state_started = true;
        }
    }

    let mut steps = Vec::with_capacity(compact_steps.len());
    let mut transitions = Vec::new();
    let mut current_traffic = CommitProgramTraffic::default();
    let mut fused_traffic = CommitProgramTraffic::default();
    let mut current_state = None;
    let mut current_log = None;
    let mut absorbed_columns = 0u32;
    let mut absorbed_batches = 0usize;
    let mut fused_compressions = 0u64;
    let mut saw_finalize = false;
    let mut index = 0usize;

    while index < compact_steps.len() {
        if saw_finalize {
            return Err(FusedCompactDomainProgramError::NonCanonicalProgram);
        }
        let step = compact_steps[index];
        match step.operation {
            CompactDomainOperation::LdeBatch {
                batch_index,
                first_column,
                columns,
                log_size,
            } => {
                current_traffic = add_traffic(current_traffic, step.traffic)?;
                fused_traffic = add_traffic(fused_traffic, step.traffic)?;
                steps.push(FusedCompactDomainStep {
                    operation: FusedCompactDomainOperation::LdeBatch {
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                    },
                    traffic: step.traffic,
                });
            }
            CompactDomainOperation::AbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                log_size,
                absorbed_columns_before,
                initializes_state,
                reconstructed_tail,
                leaf_compressions,
            } => {
                validate_absorb(
                    &batches,
                    absorbed_batches,
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                    absorbed_columns,
                    reconstructed_tail,
                    leaf_compressions,
                )?;
                let state = match current_state {
                    None if initializes_state => {
                        let len_words = compact_state_words(log_size)?;
                        DomainCooperativeSlabSlice {
                            offset_words: if initial_state_is_high {
                                state_capacity_words.checked_sub(len_words).ok_or(
                                    FusedCompactDomainProgramError::SlabCapacity {
                                        step: index,
                                        required_words: len_words,
                                        available_words: state_capacity_words,
                                    },
                                )?
                            } else {
                                0
                            },
                            len_words,
                        }
                    }
                    Some(state) if !initializes_state && current_log == Some(log_size) => state,
                    _ => return Err(FusedCompactDomainProgramError::InvalidState),
                };
                validate_span(index, state, scratch, qualified_slab_words)?;
                validate_absorb_traffic(step.traffic, state, columns, reconstructed_tail)?;
                current_traffic = add_traffic(current_traffic, step.traffic)?;
                fused_traffic = add_traffic(fused_traffic, step.traffic)?;
                fused_compressions = fused_compressions
                    .checked_add(leaf_compressions)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                steps.push(FusedCompactDomainStep {
                    operation: FusedCompactDomainOperation::AbsorbDomainBatch {
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                        absorbed_columns_before,
                        initializes_state,
                        reconstructed_tail,
                        state,
                        leaf_compressions,
                    },
                    traffic: step.traffic,
                });
                current_state = Some(state);
                current_log = Some(log_size);
                absorbed_columns = absorbed_columns
                    .checked_add(columns)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                absorbed_batches += 1;
            }
            CompactDomainOperation::StateExpandInPlace {
                from_log_size,
                to_log_size,
                absorbed_columns: expansion_absorbed,
                bands,
            } => {
                let absorb = compact_steps.get(index + 1).ok_or(
                    FusedCompactDomainProgramError::ExpansionNotFollowedByAbsorb { step: index },
                )?;
                let CompactDomainOperation::AbsorbDomainBatch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                    initializes_state,
                    reconstructed_tail,
                    leaf_compressions,
                } = absorb.operation
                else {
                    return Err(
                        FusedCompactDomainProgramError::ExpansionNotFollowedByAbsorb {
                            step: index,
                        },
                    );
                };
                if current_log != Some(from_log_size)
                    || expansion_absorbed != absorbed_columns
                    || log_size != to_log_size
                    || absorbed_columns_before != expansion_absorbed
                    || initializes_state
                {
                    return Err(FusedCompactDomainProgramError::ExpansionAbsorbMismatch {
                        step: index,
                    });
                }
                validate_absorb(
                    &batches,
                    absorbed_batches,
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                    absorbed_columns,
                    reconstructed_tail,
                    leaf_compressions,
                )?;
                let tail =
                    reconstructed_tail.ok_or(FusedCompactDomainProgramError::NonCanonicalTail)?;
                let source = current_state.ok_or(FusedCompactDomainProgramError::InvalidState)?;
                if source.len_words != compact_state_words(from_log_size)? {
                    return Err(FusedCompactDomainProgramError::InvalidState);
                }
                let destination_words = compact_state_words(to_log_size)?;
                let destination = if source.offset_words == 0 {
                    DomainCooperativeSlabSlice {
                        offset_words: state_capacity_words.checked_sub(destination_words).ok_or(
                            FusedCompactDomainProgramError::SlabCapacity {
                                step: index,
                                required_words: destination_words,
                                available_words: state_capacity_words,
                            },
                        )?,
                        len_words: destination_words,
                    }
                } else {
                    DomainCooperativeSlabSlice {
                        offset_words: 0,
                        len_words: destination_words,
                    }
                };
                let peak_words = source
                    .len_words
                    .checked_add(destination.len_words)
                    .and_then(|words| words.checked_add(scratch.len_words))
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                if peak_words > qualified_slab_words {
                    return Err(FusedCompactDomainProgramError::SlabCapacity {
                        step: index,
                        required_words: peak_words,
                        available_words: qualified_slab_words,
                    });
                }
                validate_transition_spans(
                    index,
                    source,
                    destination,
                    scratch,
                    qualified_slab_words,
                )?;
                let fused = fused_transition_traffic(
                    index,
                    step,
                    *absorb,
                    source,
                    destination,
                    columns,
                    Some(tail),
                )?;
                let pair_current = add_traffic(step.traffic, absorb.traffic)?;
                current_traffic = add_traffic(current_traffic, pair_current)?;
                fused_traffic = add_traffic(fused_traffic, fused)?;
                fused_compressions = fused_compressions
                    .checked_add(leaf_compressions)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                let destination_bytes = bytes(destination.len_words)?;
                let scratch_bytes = COMPACT_EXPANSION_SCRATCH_HASHES
                    .checked_mul(HASH_BYTES)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                let transition = FusedCompactDomainTransition {
                    batch_index,
                    from_log_size,
                    to_log_size,
                    expansion_bands: bands,
                    source_state: source,
                    destination_state: destination,
                    scratch,
                    peak_words,
                    qualified_slab_capacity_words: qualified_slab_words,
                    current_traffic: pair_current,
                    fused_traffic: fused,
                    expanded_state_write_bytes_removed: destination_bytes,
                    expanded_state_reread_bytes_removed: destination_bytes,
                    expansion_scratch_read_bytes_removed: scratch_bytes,
                    expansion_scratch_write_bytes_removed: scratch_bytes,
                    kernel_launches_removed: bands,
                    device_copies_removed: 1,
                };
                transitions.push(transition);
                steps.push(FusedCompactDomainStep {
                    operation: FusedCompactDomainOperation::ExpandAbsorbDomainBatch {
                        batch_index,
                        first_column,
                        columns,
                        from_log_size,
                        to_log_size,
                        absorbed_columns_before,
                        expansion_bands: bands,
                        reconstructed_tail: tail,
                        source_state: source,
                        destination_state: destination,
                        scratch,
                        leaf_compressions,
                    },
                    traffic: fused,
                });
                current_state = Some(destination);
                current_log = Some(to_log_size);
                absorbed_columns = absorbed_columns
                    .checked_add(columns)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                absorbed_batches += 1;
                index += 1;
            }
            CompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns: final_absorbed,
                reconstructed_tail,
                leaf_compressions,
            } => {
                if saw_finalize
                    || absorbed_batches != batches.len()
                    || final_absorbed != absorbed_columns
                    || current_log != Some(log_size)
                    || canonical_tail(final_absorbed) != Some(reconstructed_tail)
                    || leaf_compressions != row_count(log_size)?
                {
                    return Err(FusedCompactDomainProgramError::MissingFinalize);
                }
                saw_finalize = true;
                let state = current_state.ok_or(FusedCompactDomainProgramError::InvalidState)?;
                if state.offset_words != 0 || state.len_words != compact_state_words(log_size)? {
                    return Err(FusedCompactDomainProgramError::InvalidState);
                }
                validate_finalize_traffic(step.traffic, state, reconstructed_tail)?;
                current_traffic = add_traffic(current_traffic, step.traffic)?;
                fused_traffic = add_traffic(fused_traffic, step.traffic)?;
                fused_compressions = fused_compressions
                    .checked_add(leaf_compressions)
                    .ok_or(FusedCompactDomainProgramError::SizeOverflow)?;
                steps.push(FusedCompactDomainStep {
                    operation: FusedCompactDomainOperation::FinalizeInPlace {
                        log_size,
                        absorbed_columns: final_absorbed,
                        reconstructed_tail,
                        state,
                        leaf_compressions,
                    },
                    traffic: step.traffic,
                });
            }
        }
        index += 1;
    }

    if !saw_finalize || absorbed_batches != batches.len() {
        return Err(FusedCompactDomainProgramError::MissingFinalize);
    }
    if current_traffic != current.replacement_leaf_traffic {
        return Err(FusedCompactDomainProgramError::NonCanonicalTraffic);
    }
    if fused_compressions != current.replacement_leaf_compressions {
        return Err(FusedCompactDomainProgramError::CompressionMismatch {
            current: current.replacement_leaf_compressions,
            fused: fused_compressions,
        });
    }

    let receipt = receipt(
        qualified_slab_words,
        compact_slab_words,
        transitions,
        current_traffic,
        fused_traffic,
        current.replacement_leaf_compressions,
        fused_compressions,
    )?;
    Ok(FusedCompactDomainProgram {
        cache_key: cache_key(compact_cache_key, qualified_slab_words),
        steps,
        merkle_suffix: merkle_suffix.to_vec(),
        receipt,
    })
}

#[cfg(test)]
#[path = "domain_expand_absorb_tests.rs"]
mod tests;
