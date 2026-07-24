//! Pure h8-only state program for retained domain-cooperative leaves.
//!
//! The qualified Mode-A program keeps `h[8]` plus the lazy 16-word Blake2s
//! block for every native-domain row. This model keeps only `h[8]`. At each
//! later absorb or finalization it reconstructs the exact lazy tail from the
//! already-retained evaluation columns using the ordinary lifted-row mapping.
//! There is no separate "periodic column" representation in the commitment
//! path. It never lifts column hashing to the largest domain and it preserves
//! every progressive compression boundary.

use super::*;

const WORD_BYTES: u64 = core::mem::size_of::<u32>() as u64;
const HASH_WORDS: usize = core::mem::size_of::<Blake2sHash>() / core::mem::size_of::<u32>();
const HASH_BYTES: u64 = core::mem::size_of::<Blake2sHash>() as u64;
const SCRATCH_HASHES: usize = 2;
const SHARED_IN_PLACE_SCRATCH_WORDS: usize =
    super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;
const CACHE_TAG: &[u8] = b"stwo-domain-cooperative-compact-h8-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactDomainTail {
    pub first_column: u32,
    /// Blake2s lazy-final-block semantics use 16, not zero, at an exact block
    /// boundary. Every referenced column is retained by Mode A.
    pub columns: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactDomainOperation {
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
        reconstructed_tail: CompactDomainTail,
        leaf_compressions: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactDomainStep {
    pub operation: CompactDomainOperation,
    pub traffic: CommitProgramTraffic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompactDomainComparison {
    pub current_leaf_traffic: CommitProgramTraffic,
    pub replacement_leaf_traffic: CommitProgramTraffic,
    pub tail_reconstruction_read_bytes: u64,
    pub current_state_slab_words: usize,
    pub replacement_state_slab_words: usize,
    pub state_slab_words_saved: usize,
    pub current_state_api_calls: u32,
    pub replacement_state_api_calls: u32,
    pub current_leaf_compressions: u64,
    pub replacement_leaf_compressions: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactDomainProgram {
    cache_key: u64,
    steps: Vec<CompactDomainStep>,
    merkle_suffix: Vec<CommitProgramStep>,
    slab_words: usize,
    comparison: CompactDomainComparison,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactDomainProgramError {
    Domain(DomainCooperativeProgramError),
    NonCanonicalProgram,
    MissingFinalize,
    InvalidTail,
    ReadRegression { current: u64, replacement: u64 },
    CompressionMismatch { current: u64, replacement: u64 },
    SizeOverflow,
}

impl core::fmt::Display for CompactDomainProgramError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid compact domain-cooperative program: {self:?}")
    }
}

impl std::error::Error for CompactDomainProgramError {}

impl From<DomainCooperativeProgramError> for CompactDomainProgramError {
    fn from(value: DomainCooperativeProgramError) -> Self {
        Self::Domain(value)
    }
}

impl CompactDomainProgram {
    /// Compile the dormant h8-only successor from the exact qualified Mode-A
    /// program. Constructing this pure model cannot select a native launch.
    pub fn compile(
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
    ) -> Result<Self, CompactDomainProgramError> {
        let program = Self::compile_canonical(base, domain)?;
        program.validate_against(base, domain)?;
        Ok(program)
    }

    pub fn validate_against(
        &self,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
    ) -> Result<(), CompactDomainProgramError> {
        domain.validate_against(base)?;
        if *self == Self::compile_canonical(base, domain)? {
            Ok(())
        } else {
            Err(CompactDomainProgramError::NonCanonicalProgram)
        }
    }

    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub fn steps(&self) -> &[CompactDomainStep] {
        &self.steps
    }

    pub fn merkle_suffix(&self) -> &[CommitProgramStep] {
        &self.merkle_suffix
    }

    pub fn slab_words(&self) -> usize {
        self.slab_words
    }

    pub fn comparison(&self) -> CompactDomainComparison {
        self.comparison
    }

    fn compile_canonical(
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
    ) -> Result<Self, CompactDomainProgramError> {
        domain.validate_against(base)?;
        let mut steps = Vec::with_capacity(domain.steps().len());
        let mut traffic = CommitProgramTraffic::default();
        let mut tail_reconstruction_read_bytes = 0u64;
        let mut compact_compressions = 0u64;
        let mut saw_finalize = false;

        for step in domain.steps() {
            let compact = match step.operation {
                DomainCooperativeOperation::LdeBatch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                } => CompactDomainStep {
                    operation: CompactDomainOperation::LdeBatch {
                        batch_index,
                        first_column,
                        columns,
                        log_size,
                    },
                    traffic: step.traffic,
                },
                DomainCooperativeOperation::AbsorbDomainBatch {
                    batch_index,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                    initializes_state,
                    leaf_compressions,
                    ..
                } => {
                    let tail = tail(absorbed_columns_before)?;
                    if initializes_state != tail.is_none() {
                        return Err(CompactDomainProgramError::InvalidTail);
                    }
                    let rows = rows(log_size)?;
                    let evaluation_bytes = rows
                        .checked_mul(u64::from(columns))
                        .and_then(|words| words.checked_mul(WORD_BYTES))
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    let tail_bytes = rows
                        .checked_mul(u64::from(tail.map_or(0, |tail| tail.columns)))
                        .and_then(|words| words.checked_mul(WORD_BYTES))
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    tail_reconstruction_read_bytes = tail_reconstruction_read_bytes
                        .checked_add(tail_bytes)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    let state_bytes = rows
                        .checked_mul(HASH_BYTES)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    compact_compressions = compact_compressions
                        .checked_add(leaf_compressions)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    CompactDomainStep {
                        operation: CompactDomainOperation::AbsorbDomainBatch {
                            batch_index,
                            first_column,
                            columns,
                            log_size,
                            absorbed_columns_before,
                            initializes_state,
                            reconstructed_tail: tail,
                            leaf_compressions,
                        },
                        traffic: CommitProgramTraffic {
                            owned_read_bytes: evaluation_bytes
                                .checked_add(tail_bytes)
                                .and_then(|bytes| {
                                    bytes.checked_add(if initializes_state {
                                        0
                                    } else {
                                        state_bytes
                                    })
                                })
                                .ok_or(CompactDomainProgramError::SizeOverflow)?,
                            owned_write_bytes: state_bytes,
                            kernel_launches: 1,
                            device_copies: 0,
                        },
                    }
                }
                DomainCooperativeOperation::StateExpandInPlace {
                    from_log_size,
                    to_log_size,
                    absorbed_columns,
                    bands,
                } => {
                    // Expansion copies only h[8]. It deliberately does not
                    // reconstruct the lazy tail; the next absorb/finalize
                    // reads that tail from retained evaluations at its target
                    // domain. The two saved hashes are copied to scratch and
                    // read once by the destructive final band.
                    let scratch_bytes = (SCRATCH_HASHES as u64) * HASH_BYTES;
                    let read_bytes = rows(from_log_size)?
                        .checked_mul(HASH_BYTES)
                        .and_then(|bytes| bytes.checked_add(scratch_bytes))
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    let write_bytes = rows(to_log_size)?
                        .checked_mul(HASH_BYTES)
                        .and_then(|bytes| bytes.checked_add(scratch_bytes))
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    CompactDomainStep {
                        operation: CompactDomainOperation::StateExpandInPlace {
                            from_log_size,
                            to_log_size,
                            absorbed_columns,
                            bands,
                        },
                        traffic: CommitProgramTraffic {
                            owned_read_bytes: read_bytes,
                            owned_write_bytes: write_bytes,
                            kernel_launches: bands,
                            device_copies: 1,
                        },
                    }
                }
                DomainCooperativeOperation::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    leaf_compressions,
                    ..
                } => {
                    if saw_finalize {
                        return Err(CompactDomainProgramError::MissingFinalize);
                    }
                    saw_finalize = true;
                    let tail =
                        tail(absorbed_columns)?.ok_or(CompactDomainProgramError::InvalidTail)?;
                    let rows = rows(log_size)?;
                    let state_bytes = rows
                        .checked_mul(HASH_BYTES)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    let tail_bytes = rows
                        .checked_mul(u64::from(tail.columns))
                        .and_then(|words| words.checked_mul(WORD_BYTES))
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    tail_reconstruction_read_bytes = tail_reconstruction_read_bytes
                        .checked_add(tail_bytes)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    compact_compressions = compact_compressions
                        .checked_add(leaf_compressions)
                        .ok_or(CompactDomainProgramError::SizeOverflow)?;
                    CompactDomainStep {
                        operation: CompactDomainOperation::FinalizeInPlace {
                            log_size,
                            absorbed_columns,
                            reconstructed_tail: tail,
                            leaf_compressions,
                        },
                        traffic: CommitProgramTraffic {
                            owned_read_bytes: state_bytes
                                .checked_add(tail_bytes)
                                .ok_or(CompactDomainProgramError::SizeOverflow)?,
                            owned_write_bytes: state_bytes,
                            kernel_launches: 1,
                            device_copies: 0,
                        },
                    }
                }
            };
            traffic = add_traffic(traffic, compact.traffic)?;
            steps.push(compact);
        }
        if !saw_finalize {
            return Err(CompactDomainProgramError::MissingFinalize);
        }

        let current = domain.comparison();
        if compact_compressions != current.replacement_leaf_compressions {
            return Err(CompactDomainProgramError::CompressionMismatch {
                current: current.replacement_leaf_compressions,
                replacement: compact_compressions,
            });
        }
        if traffic.owned_read_bytes > current.replacement_leaf_traffic.owned_read_bytes {
            return Err(CompactDomainProgramError::ReadRegression {
                current: current.replacement_leaf_traffic.owned_read_bytes,
                replacement: traffic.owned_read_bytes,
            });
        }
        let slab_words = rows_usize(base.identity().config.lifting_log_size)?
            .checked_mul(HASH_WORDS)
            // Preserve the qualified progressive/Merkle one-slab admission
            // contract. Compact expansion uses only two saved hashes, but the
            // shared suffix still requires its existing 48-word tail.
            .and_then(|words| words.checked_add(SHARED_IN_PLACE_SCRATCH_WORDS))
            .ok_or(CompactDomainProgramError::SizeOverflow)?;
        let saved = domain
            .slab_words()
            .checked_sub(slab_words)
            .ok_or(CompactDomainProgramError::SizeOverflow)?;
        let state_api_calls = u32::try_from(
            steps
                .iter()
                .filter(|step| !matches!(step.operation, CompactDomainOperation::LdeBatch { .. }))
                .count(),
        )
        .map_err(|_| CompactDomainProgramError::SizeOverflow)?;
        let comparison = CompactDomainComparison {
            current_leaf_traffic: current.replacement_leaf_traffic,
            replacement_leaf_traffic: traffic,
            tail_reconstruction_read_bytes,
            current_state_slab_words: domain.slab_words(),
            replacement_state_slab_words: slab_words,
            state_slab_words_saved: saved,
            current_state_api_calls: current.replacement_state_api_calls,
            replacement_state_api_calls: state_api_calls,
            current_leaf_compressions: current.replacement_leaf_compressions,
            replacement_leaf_compressions: compact_compressions,
        };
        Ok(Self {
            cache_key: cache_key(domain.cache_key()),
            steps,
            merkle_suffix: domain.merkle_suffix().to_vec(),
            slab_words,
            comparison,
        })
    }
}

fn tail(absorbed_columns: u32) -> Result<Option<CompactDomainTail>, CompactDomainProgramError> {
    if absorbed_columns == 0 {
        return Ok(None);
    }
    let columns = (absorbed_columns - 1) % 16 + 1;
    Ok(Some(CompactDomainTail {
        first_column: absorbed_columns
            .checked_sub(columns)
            .ok_or(CompactDomainProgramError::InvalidTail)?,
        columns,
    }))
}

fn add_traffic(
    left: CommitProgramTraffic,
    right: CommitProgramTraffic,
) -> Result<CommitProgramTraffic, CompactDomainProgramError> {
    Ok(CommitProgramTraffic {
        owned_read_bytes: left
            .owned_read_bytes
            .checked_add(right.owned_read_bytes)
            .ok_or(CompactDomainProgramError::SizeOverflow)?,
        owned_write_bytes: left
            .owned_write_bytes
            .checked_add(right.owned_write_bytes)
            .ok_or(CompactDomainProgramError::SizeOverflow)?,
        kernel_launches: left
            .kernel_launches
            .checked_add(right.kernel_launches)
            .ok_or(CompactDomainProgramError::SizeOverflow)?,
        device_copies: left
            .device_copies
            .checked_add(right.device_copies)
            .ok_or(CompactDomainProgramError::SizeOverflow)?,
    })
}

fn rows(log_size: u32) -> Result<u64, CompactDomainProgramError> {
    1u64.checked_shl(log_size)
        .ok_or(CompactDomainProgramError::SizeOverflow)
}

fn rows_usize(log_size: u32) -> Result<usize, CompactDomainProgramError> {
    1usize
        .checked_shl(log_size)
        .ok_or(CompactDomainProgramError::SizeOverflow)
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
#[path = "domain_compact_tests.rs"]
mod tests;
