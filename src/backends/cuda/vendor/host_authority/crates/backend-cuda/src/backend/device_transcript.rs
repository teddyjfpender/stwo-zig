//! Prepared ordinary-Blake2s Fiat-Shamir transcript for resident CUDA proofs.
//!
//! The protocol tag below identifies the launch/snapshot ABI only; it is never
//! mixed into the cryptographic transcript. Each operation implements the exact
//! byte stream of [`Blake2sChannel`]. Launches use only caller-owned arena ranges
//! and the proof's explicit stream. A device snapshot is retained after every
//! operation, and migration is fail-closed until [`PreparedBlake2sTranscript::verify_mirror`]
//! proves digest, draw-counter, challenge, query, and operation-chain equality
//! against the reference host channel.

use core::ffi::c_void;
use core::ops::Range;
use std::collections::{BTreeMap, BTreeSet};

use stwo::core::channel::{Blake2sChannel, Channel, MerkleChannel};
use stwo::core::fields::m31::{BaseField, P};
use stwo::core::fields::qm31::SecureField;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleChannel;

use super::exec_context::{
    check_cuda, ArenaError, ArenaSlice, ArenaSlotId, CudaRuntimeError, DeviceArena,
};

const WORD_BYTES: usize = core::mem::size_of::<u32>();
pub const BLAKE2S_TRANSCRIPT_PROTOCOL_TAG: &str = "stwo.blake2s.transcript.device.v1";
pub const BLAKE2S_TRANSCRIPT_STATE_WORDS: usize = 16;
pub const BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS: usize = 8;
const SEED_WORDS: usize = 9;
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const MAX_BLAKE_MIX_WORDS: usize = (u32::MAX as usize - 32) / WORD_BYTES;
const MAX_SEED_DRAWS: u32 = 1 << 20;

fn query_position(word: u32, log_domain_size: u32) -> u32 {
    let mask = if log_domain_size == 0 {
        0
    } else {
        (1u32 << log_domain_size) - 1
    };
    word & mask
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TranscriptInputId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TranscriptOutputId(pub u32);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TranscriptBoundaryId(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptStart {
    Default,
    DeviceState(TranscriptInputId),
}

/// One exact `Blake2sChannel` operation. Sources and destinations are logical
/// identities bound to stable [`ArenaSlice`] values during preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptOperation {
    MixFelts {
        boundary: TranscriptBoundaryId,
        source: TranscriptInputId,
        n_felts: u32,
    },
    MixU32s {
        boundary: TranscriptBoundaryId,
        source: TranscriptInputId,
        n_words: u32,
    },
    MixU64 {
        boundary: TranscriptBoundaryId,
        source: TranscriptInputId,
    },
    AbsorbRoot {
        boundary: TranscriptBoundaryId,
        source: TranscriptInputId,
    },
    /// Verify the nonce against the current digest, then apply `mix_u64`.
    /// This typed boundary prevents an unchecked PoW scalar from entering the
    /// resident transcript during migration.
    AbsorbPowNonce {
        boundary: TranscriptBoundaryId,
        source: TranscriptInputId,
        pow_bits: u32,
    },
    DrawSecureFelt {
        boundary: TranscriptBoundaryId,
        output: TranscriptOutputId,
    },
    /// Matches the batched channel method exactly, including discarding the
    /// second secure felt from the final eight-word draw when `n_felts` is odd.
    DrawSecureFelts {
        boundary: TranscriptBoundaryId,
        output: TranscriptOutputId,
        n_felts: u32,
    },
    DrawU32s {
        boundary: TranscriptBoundaryId,
        output: TranscriptOutputId,
    },
    /// Produces raw query positions in draw order. Sorting/deduplication into
    /// `Queries` is a separate deterministic proof-driver operation.
    DrawQueries {
        boundary: TranscriptBoundaryId,
        output: TranscriptOutputId,
        log_domain_size: u32,
        n_queries: u32,
    },
}

impl TranscriptOperation {
    pub fn boundary(&self) -> TranscriptBoundaryId {
        match *self {
            Self::MixFelts { boundary, .. }
            | Self::MixU32s { boundary, .. }
            | Self::MixU64 { boundary, .. }
            | Self::AbsorbRoot { boundary, .. }
            | Self::AbsorbPowNonce { boundary, .. }
            | Self::DrawSecureFelt { boundary, .. }
            | Self::DrawSecureFelts { boundary, .. }
            | Self::DrawU32s { boundary, .. }
            | Self::DrawQueries { boundary, .. } => boundary,
        }
    }

    fn input(&self) -> Result<Option<(TranscriptInputId, usize)>, DeviceTranscriptError> {
        Ok(match *self {
            Self::MixFelts {
                source, n_felts, ..
            } => Some((source, checked_words(n_felts, 4)?)),
            Self::MixU32s {
                source, n_words, ..
            } => Some((source, nonzero_words(n_words)?)),
            Self::MixU64 { source, .. } | Self::AbsorbPowNonce { source, .. } => Some((source, 2)),
            Self::AbsorbRoot { source, .. } => Some((source, 8)),
            Self::DrawSecureFelt { .. }
            | Self::DrawSecureFelts { .. }
            | Self::DrawU32s { .. }
            | Self::DrawQueries { .. } => None,
        })
    }

    fn output(&self) -> Result<Option<(TranscriptOutputId, usize)>, DeviceTranscriptError> {
        Ok(match *self {
            Self::DrawSecureFelt { output, .. } => Some((output, 4)),
            Self::DrawSecureFelts {
                output, n_felts, ..
            } => Some((output, checked_words(n_felts, 4)?)),
            Self::DrawU32s { output, .. } => Some((output, 8)),
            Self::DrawQueries {
                output, n_queries, ..
            } => Some((output, nonzero_words(n_queries)?)),
            Self::MixFelts { .. }
            | Self::MixU32s { .. }
            | Self::MixU64 { .. }
            | Self::AbsorbRoot { .. }
            | Self::AbsorbPowNonce { .. } => None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptIoRequirement<I> {
    pub id: I,
    pub min_words: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake2sTranscriptRequirements {
    pub state_words: usize,
    pub boundary_snapshot_words: usize,
    pub input_snapshot_words: usize,
    pub input_snapshot_used_words: usize,
    pub output_snapshot_words: usize,
    pub output_snapshot_used_words: usize,
    pub inputs: Vec<TranscriptIoRequirement<TranscriptInputId>>,
    pub outputs: Vec<TranscriptIoRequirement<TranscriptOutputId>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TranscriptArenaSlotRequirement {
    pub id: ArenaSlotId,
    pub len_words: usize,
    pub alignment_words: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Blake2sTranscriptWorkspaceSlots {
    pub state: ArenaSlotId,
    pub boundary_snapshots: ArenaSlotId,
    pub input_snapshots: ArenaSlotId,
    pub output_snapshots: ArenaSlotId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blake2sTranscriptSchedule {
    start: TranscriptStart,
    operations: Vec<TranscriptOperation>,
    max_rejection_rounds: u32,
    prefix_chains: Vec<u64>,
    requirements: Blake2sTranscriptRequirements,
}

impl Blake2sTranscriptSchedule {
    pub fn new(
        start: TranscriptStart,
        operations: Vec<TranscriptOperation>,
        max_rejection_rounds: u32,
    ) -> Result<Self, DeviceTranscriptError> {
        if operations.is_empty() {
            return Err(DeviceTranscriptError::EmptySchedule);
        }
        if max_rejection_rounds == 0 {
            return Err(DeviceTranscriptError::InvalidRejectionLimit);
        }
        u32::try_from(operations.len()).map_err(|_| DeviceTranscriptError::SizeOverflow)?;

        let mut boundaries = BTreeSet::new();
        let mut produced_outputs = BTreeSet::new();
        let mut input_sizes = BTreeMap::<TranscriptInputId, usize>::new();
        let mut output_sizes = BTreeMap::<TranscriptOutputId, usize>::new();
        let mut input_snapshot_used_words = match start {
            TranscriptStart::Default => 0usize,
            TranscriptStart::DeviceState(id) => {
                input_sizes.insert(id, SEED_WORDS);
                SEED_WORDS
            }
        };
        let mut output_snapshot_used_words = 0usize;

        for operation in &operations {
            if !boundaries.insert(operation.boundary()) {
                return Err(DeviceTranscriptError::DuplicateBoundary(
                    operation.boundary(),
                ));
            }
            match *operation {
                TranscriptOperation::MixFelts { n_felts, .. }
                | TranscriptOperation::DrawSecureFelts { n_felts, .. } => {
                    if n_felts == 0 {
                        return Err(DeviceTranscriptError::ZeroLengthOperation);
                    }
                }
                TranscriptOperation::MixU32s { n_words, .. } if n_words == 0 => {
                    return Err(DeviceTranscriptError::ZeroLengthOperation);
                }
                TranscriptOperation::AbsorbPowNonce { pow_bits, .. } if pow_bits > 128 => {
                    return Err(DeviceTranscriptError::InvalidPowBits(pow_bits));
                }
                TranscriptOperation::DrawQueries {
                    log_domain_size,
                    n_queries,
                    ..
                } => {
                    if log_domain_size >= 32 {
                        return Err(DeviceTranscriptError::InvalidQueryDomain(log_domain_size));
                    }
                    if n_queries == 0 {
                        return Err(DeviceTranscriptError::ZeroLengthOperation);
                    }
                }
                _ => {}
            }
            if let Some((id, words)) = operation.input()? {
                if matches!(
                    operation,
                    TranscriptOperation::MixFelts { .. } | TranscriptOperation::MixU32s { .. }
                ) && words > MAX_BLAKE_MIX_WORDS
                {
                    return Err(DeviceTranscriptError::MessageTooLong(words));
                }
                input_snapshot_used_words = input_snapshot_used_words
                    .checked_add(words)
                    .ok_or(DeviceTranscriptError::SizeOverflow)?;
                input_sizes
                    .entry(id)
                    .and_modify(|current| *current = (*current).max(words))
                    .or_insert(words);
            }
            if let Some((id, words)) = operation.output()? {
                if !produced_outputs.insert(id) {
                    return Err(DeviceTranscriptError::DuplicateOutput(id));
                }
                output_snapshot_used_words = output_snapshot_used_words
                    .checked_add(words)
                    .ok_or(DeviceTranscriptError::SizeOverflow)?;
                output_sizes.insert(id, words);
            }
        }

        let boundary_snapshot_words = operations
            .len()
            .checked_mul(BLAKE2S_TRANSCRIPT_STATE_WORDS)
            .ok_or(DeviceTranscriptError::SizeOverflow)?;
        let requirements = Blake2sTranscriptRequirements {
            state_words: BLAKE2S_TRANSCRIPT_STATE_WORDS,
            boundary_snapshot_words,
            // Arena layouts reject empty slots. One unused sentinel word keeps
            // all schedule shapes uniform without adding launch work.
            input_snapshot_words: input_snapshot_used_words.max(1),
            input_snapshot_used_words,
            output_snapshot_words: output_snapshot_used_words.max(1),
            output_snapshot_used_words,
            inputs: input_sizes
                .into_iter()
                .map(|(id, min_words)| TranscriptIoRequirement { id, min_words })
                .collect(),
            outputs: output_sizes
                .into_iter()
                .map(|(id, min_words)| TranscriptIoRequirement { id, min_words })
                .collect(),
        };

        let mut chain = StableHash::new();
        chain.bytes(BLAKE2S_TRANSCRIPT_PROTOCOL_TAG.as_bytes());
        chain.u32(max_rejection_rounds);
        match start {
            TranscriptStart::Default => chain.u32(0),
            TranscriptStart::DeviceState(id) => {
                chain.u32(1);
                chain.u32(id.0);
            }
        }
        let mut prefix_chains = Vec::with_capacity(operations.len() + 1);
        prefix_chains.push(chain.finish());
        for operation in &operations {
            hash_operation(&mut chain, operation);
            prefix_chains.push(chain.finish());
        }

        Ok(Self {
            start,
            operations,
            max_rejection_rounds,
            prefix_chains,
            requirements,
        })
    }

    pub fn protocol_tag(&self) -> &'static str {
        BLAKE2S_TRANSCRIPT_PROTOCOL_TAG
    }

    pub fn protocol_key(&self) -> u64 {
        *self
            .prefix_chains
            .last()
            .expect("validated schedules contain operations")
    }

    pub fn initial_chain(&self) -> u64 {
        self.prefix_chains[0]
    }

    pub fn start(&self) -> TranscriptStart {
        self.start
    }

    pub fn operations(&self) -> &[TranscriptOperation] {
        &self.operations
    }

    pub fn max_rejection_rounds(&self) -> u32 {
        self.max_rejection_rounds
    }

    pub fn requirements(&self) -> &Blake2sTranscriptRequirements {
        &self.requirements
    }
}

impl Blake2sTranscriptRequirements {
    pub fn arena_slot_requirements(
        &self,
        slots: Blake2sTranscriptWorkspaceSlots,
    ) -> Result<Vec<TranscriptArenaSlotRequirement>, DeviceTranscriptError> {
        let requirements = vec![
            TranscriptArenaSlotRequirement {
                id: slots.state,
                len_words: self.state_words,
                alignment_words: BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS,
            },
            TranscriptArenaSlotRequirement {
                id: slots.boundary_snapshots,
                len_words: self.boundary_snapshot_words,
                alignment_words: BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS,
            },
            TranscriptArenaSlotRequirement {
                id: slots.input_snapshots,
                len_words: self.input_snapshot_words,
                alignment_words: 1,
            },
            TranscriptArenaSlotRequirement {
                id: slots.output_snapshots,
                len_words: self.output_snapshot_words,
                alignment_words: 1,
            },
        ];
        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !seen.insert(requirement.id) {
                return Err(DeviceTranscriptError::DuplicateWorkspaceSlot(
                    requirement.id,
                ));
            }
        }
        Ok(requirements)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TranscriptInputBinding {
    pub id: TranscriptInputId,
    pub slice: ArenaSlice,
}

#[derive(Clone, Copy, Debug)]
pub struct TranscriptOutputBinding {
    pub id: TranscriptOutputId,
    pub slice: ArenaSlice,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeviceTranscriptError {
    EmptySchedule,
    InvalidRejectionLimit,
    ZeroLengthOperation,
    InvalidPowBits(u32),
    InvalidQueryDomain(u32),
    MessageTooLong(usize),
    DuplicateBoundary(TranscriptBoundaryId),
    DuplicateOutput(TranscriptOutputId),
    DuplicateInputBinding(TranscriptInputId),
    DuplicateOutputBinding(TranscriptOutputId),
    MissingInputBinding(TranscriptInputId),
    MissingOutputBinding(TranscriptOutputId),
    BindingTooSmall {
        role: &'static str,
        id: u32,
        required_words: usize,
        actual_words: usize,
    },
    ContextMismatch(ArenaSlotId),
    WorkspaceAlias(ArenaSlotId),
    DuplicateWorkspaceSlot(ArenaSlotId),
    SlotTooSmall {
        slot: ArenaSlotId,
        required_words: usize,
        actual_words: usize,
    },
    MisalignedSlot {
        slot: ArenaSlotId,
        alignment_words: usize,
    },
    InputSnapshotLength {
        expected_words: usize,
        actual_words: usize,
    },
    DeviceStatus {
        boundary: TranscriptBoundaryId,
        status: u32,
    },
    OperationOrderDivergence {
        boundary: TranscriptBoundaryId,
        expected_cursor: u32,
        actual_cursor: u32,
    },
    OperationChainDivergence {
        boundary: TranscriptBoundaryId,
        expected_chain: u64,
        actual_chain: u64,
    },
    DigestDivergence(TranscriptBoundaryId),
    DrawCounterDivergence {
        boundary: TranscriptBoundaryId,
        expected: u32,
        actual: u32,
    },
    OutputDivergence,
    InvalidFieldInput(TranscriptBoundaryId),
    InvalidSeedDrawCount(u32),
    InvalidPowNonce(TranscriptBoundaryId),
    RejectionLimit(TranscriptBoundaryId),
    SegmentProtocolMismatch {
        expected: u64,
        actual: u64,
    },
    StaleSegmentGeneration {
        previous: u64,
        actual: u64,
    },
    SegmentGenerationMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidSegmentRange {
        start: usize,
        end: usize,
        operation_count: usize,
    },
    SegmentStartMismatch {
        expected: TranscriptSegmentStart,
        actual: TranscriptSegmentStart,
    },
    OutOfOrderSegment {
        expected_start: usize,
        actual_start: usize,
    },
    IncompleteSegmentSequence {
        next_operation: usize,
        operation_count: usize,
    },
    SizeOverflow,
    Arena(ArenaError),
    Cuda(CudaRuntimeError),
}

impl core::fmt::Display for DeviceTranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid prepared CUDA Blake2s transcript: {self:?}")
    }
}

impl std::error::Error for DeviceTranscriptError {}

impl From<ArenaError> for DeviceTranscriptError {
    fn from(value: ArenaError) -> Self {
        Self::Arena(value)
    }
}

impl From<CudaRuntimeError> for DeviceTranscriptError {
    fn from(value: CudaRuntimeError) -> Self {
        Self::Cuda(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptBoundaryState {
    pub boundary: TranscriptBoundaryId,
    pub digest: Blake2sHash,
    pub n_draws: u32,
    pub cursor: u32,
    pub chain: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptReferenceTrace {
    pub boundaries: Vec<TranscriptBoundaryState>,
    pub output_words: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptMirrorReport {
    pub protocol_key: u64,
    pub boundaries_verified: usize,
    pub output_words_verified: usize,
    pub final_digest: Blake2sHash,
    pub final_n_draws: u32,
}

/// Whether a captured/eager segment owns transcript initialization or resumes
/// the state written by the immediately preceding segment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TranscriptSegmentStart {
    Initialize,
    Resume,
}

/// Allocation-free host guard shared by eager launches and captured-graph
/// replay. It never owns device state; it only prevents a stale generation or
/// a skipped/reordered range from becoming transcript-authoritative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TranscriptSegmentCursor {
    protocol_key: u64,
    operation_count: usize,
    generation: u64,
    next_operation: usize,
    initialized: bool,
}

impl TranscriptSegmentCursor {
    pub fn new(schedule: &Blake2sTranscriptSchedule) -> Self {
        Self {
            protocol_key: schedule.protocol_key(),
            operation_count: schedule.operations().len(),
            generation: 0,
            next_operation: 0,
            initialized: false,
        }
    }

    /// Begin a strictly newer proof/capture generation.
    pub fn begin_generation(&mut self, generation: u64) -> Result<(), DeviceTranscriptError> {
        if generation == 0 || generation <= self.generation {
            return Err(DeviceTranscriptError::StaleSegmentGeneration {
                previous: self.generation,
                actual: generation,
            });
        }
        self.generation = generation;
        self.next_operation = 0;
        self.initialized = false;
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn next_operation(&self) -> usize {
        self.next_operation
    }

    pub fn is_complete(&self) -> bool {
        self.initialized && self.next_operation == self.operation_count
    }

    /// Validate and advance one captured graph replay without launching its
    /// kernels. Eager/capture launch calls the same admission internally.
    pub fn admit_segment(
        &mut self,
        schedule: &Blake2sTranscriptSchedule,
        generation: u64,
        range: Range<usize>,
        start: TranscriptSegmentStart,
    ) -> Result<(), DeviceTranscriptError> {
        self.validate_segment(schedule, generation, &range, start)?;
        self.initialized = true;
        self.next_operation = range.end;
        Ok(())
    }

    pub fn require_complete(&self) -> Result<(), DeviceTranscriptError> {
        if !self.is_complete() {
            return Err(DeviceTranscriptError::IncompleteSegmentSequence {
                next_operation: self.next_operation,
                operation_count: self.operation_count,
            });
        }
        Ok(())
    }

    fn validate_segment(
        &self,
        schedule: &Blake2sTranscriptSchedule,
        generation: u64,
        range: &Range<usize>,
        start: TranscriptSegmentStart,
    ) -> Result<(), DeviceTranscriptError> {
        if schedule.protocol_key() != self.protocol_key
            || schedule.operations().len() != self.operation_count
        {
            return Err(DeviceTranscriptError::SegmentProtocolMismatch {
                expected: self.protocol_key,
                actual: schedule.protocol_key(),
            });
        }
        if generation != self.generation || generation == 0 {
            return Err(DeviceTranscriptError::SegmentGenerationMismatch {
                expected: self.generation,
                actual: generation,
            });
        }
        if range.start >= range.end || range.end > self.operation_count {
            return Err(DeviceTranscriptError::InvalidSegmentRange {
                start: range.start,
                end: range.end,
                operation_count: self.operation_count,
            });
        }
        let expected_start = if self.initialized {
            TranscriptSegmentStart::Resume
        } else {
            TranscriptSegmentStart::Initialize
        };
        if start != expected_start {
            return Err(DeviceTranscriptError::SegmentStartMismatch {
                expected: expected_start,
                actual: start,
            });
        }
        if range.start != self.next_operation {
            return Err(DeviceTranscriptError::OutOfOrderSegment {
                expected_start: self.next_operation,
                actual_start: range.start,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct PreparedOperation {
    operation_index: u32,
    operation: TranscriptOperation,
    source: Option<ArenaSlice>,
    output: Option<ArenaSlice>,
    input_snapshot_offset: usize,
    output_snapshot_offset: usize,
    chain_before: u64,
    chain_after: u64,
}

/// A prepared transcript segment. It is intentionally not wired into the
/// default prover path: callers must explicitly launch and then pass the mirror
/// gate before treating any device challenge as transcript-authoritative.
pub struct PreparedBlake2sTranscript<'a> {
    arena: &'a DeviceArena,
    schedule: Blake2sTranscriptSchedule,
    state: ArenaSlice,
    boundary_snapshots: ArenaSlice,
    input_snapshots: ArenaSlice,
    output_snapshots: ArenaSlice,
    seed: Option<ArenaSlice>,
    operations: Vec<PreparedOperation>,
}

impl<'a> PreparedBlake2sTranscript<'a> {
    pub fn prepare(
        arena: &'a DeviceArena,
        schedule: Blake2sTranscriptSchedule,
        slots: Blake2sTranscriptWorkspaceSlots,
        input_bindings: &[TranscriptInputBinding],
        output_bindings: &[TranscriptOutputBinding],
    ) -> Result<Self, DeviceTranscriptError> {
        let slot_requirements = schedule.requirements().arena_slot_requirements(slots)?;
        let workspace_ids: BTreeSet<_> = slot_requirements.iter().map(|item| item.id).collect();
        let state = bind_slot(
            arena,
            slots.state,
            schedule.requirements().state_words,
            BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS,
        )?;
        let boundary_snapshots = bind_slot(
            arena,
            slots.boundary_snapshots,
            schedule.requirements().boundary_snapshot_words,
            BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS,
        )?;
        let input_snapshots = bind_slot(
            arena,
            slots.input_snapshots,
            schedule.requirements().input_snapshot_words,
            1,
        )?;
        let output_snapshots = bind_slot(
            arena,
            slots.output_snapshots,
            schedule.requirements().output_snapshot_words,
            1,
        )?;

        let context_token = arena.context().identity_token();
        let mut inputs = BTreeMap::new();
        for binding in input_bindings {
            if binding.slice.context_token() != context_token {
                return Err(DeviceTranscriptError::ContextMismatch(binding.slice.id()));
            }
            if workspace_ids.contains(&binding.slice.id()) {
                return Err(DeviceTranscriptError::WorkspaceAlias(binding.slice.id()));
            }
            if inputs.insert(binding.id, binding.slice).is_some() {
                return Err(DeviceTranscriptError::DuplicateInputBinding(binding.id));
            }
        }
        let mut outputs = BTreeMap::new();
        for binding in output_bindings {
            if binding.slice.context_token() != context_token {
                return Err(DeviceTranscriptError::ContextMismatch(binding.slice.id()));
            }
            if workspace_ids.contains(&binding.slice.id()) {
                return Err(DeviceTranscriptError::WorkspaceAlias(binding.slice.id()));
            }
            if outputs.insert(binding.id, binding.slice).is_some() {
                return Err(DeviceTranscriptError::DuplicateOutputBinding(binding.id));
            }
        }
        for requirement in &schedule.requirements().inputs {
            let slice = inputs
                .get(&requirement.id)
                .ok_or(DeviceTranscriptError::MissingInputBinding(requirement.id))?;
            if slice.len_words() < requirement.min_words {
                return Err(DeviceTranscriptError::BindingTooSmall {
                    role: "input",
                    id: requirement.id.0,
                    required_words: requirement.min_words,
                    actual_words: slice.len_words(),
                });
            }
        }
        for requirement in &schedule.requirements().outputs {
            let slice = outputs
                .get(&requirement.id)
                .ok_or(DeviceTranscriptError::MissingOutputBinding(requirement.id))?;
            if slice.len_words() < requirement.min_words {
                return Err(DeviceTranscriptError::BindingTooSmall {
                    role: "output",
                    id: requirement.id.0,
                    required_words: requirement.min_words,
                    actual_words: slice.len_words(),
                });
            }
        }

        let seed = match schedule.start() {
            TranscriptStart::Default => None,
            TranscriptStart::DeviceState(id) => Some(
                *inputs
                    .get(&id)
                    .ok_or(DeviceTranscriptError::MissingInputBinding(id))?,
            ),
        };
        let mut input_snapshot_offset = seed.map_or(0, |_| SEED_WORDS);
        let mut output_snapshot_offset = 0usize;
        let mut prepared_operations = Vec::with_capacity(schedule.operations().len());
        for (index, operation) in schedule.operations().iter().cloned().enumerate() {
            let source = operation
                .input()?
                .map(|(id, _)| {
                    inputs
                        .get(&id)
                        .copied()
                        .ok_or(DeviceTranscriptError::MissingInputBinding(id))
                })
                .transpose()?;
            let output = operation
                .output()?
                .map(|(id, _)| {
                    outputs
                        .get(&id)
                        .copied()
                        .ok_or(DeviceTranscriptError::MissingOutputBinding(id))
                })
                .transpose()?;
            let this_input_offset = input_snapshot_offset;
            let this_output_offset = output_snapshot_offset;
            input_snapshot_offset = input_snapshot_offset
                .checked_add(operation.input()?.map_or(0, |(_, words)| words))
                .ok_or(DeviceTranscriptError::SizeOverflow)?;
            output_snapshot_offset = output_snapshot_offset
                .checked_add(operation.output()?.map_or(0, |(_, words)| words))
                .ok_or(DeviceTranscriptError::SizeOverflow)?;
            prepared_operations.push(PreparedOperation {
                operation_index: u32::try_from(index)
                    .map_err(|_| DeviceTranscriptError::SizeOverflow)?,
                operation,
                source,
                output,
                input_snapshot_offset: this_input_offset,
                output_snapshot_offset: this_output_offset,
                chain_before: schedule.prefix_chains[index],
                chain_after: schedule.prefix_chains[index + 1],
            });
        }

        Ok(Self {
            arena,
            schedule,
            state,
            boundary_snapshots,
            input_snapshots,
            output_snapshots,
            seed,
            operations: prepared_operations,
        })
    }

    pub fn schedule(&self) -> &Blake2sTranscriptSchedule {
        &self.schedule
    }

    pub fn state(&self) -> ArenaSlice {
        self.state
    }

    pub fn segment_cursor(&self) -> TranscriptSegmentCursor {
        TranscriptSegmentCursor::new(&self.schedule)
    }

    /// Enqueue the full schedule. This is the compatibility composition of one
    /// initialized segment; graph runtimes should use [`Self::launch_segment`]
    /// at the transcript dependency ranges supplied by their protocol plan.
    pub fn launch(&self) -> Result<(), DeviceTranscriptError> {
        let mut cursor = self.segment_cursor();
        cursor.begin_generation(1)?;
        self.launch_segment(
            &mut cursor,
            1,
            0..self.operations.len(),
            TranscriptSegmentStart::Initialize,
        )?;
        cursor.require_complete()
    }

    /// Enqueue one exact contiguous range in eager execution or CUDA graph
    /// capture. Initialization is emitted exactly once at operation zero;
    /// resumed ranges consume the state left by the preceding range. The call
    /// performs no allocation, transfer, synchronization, or default-stream
    /// work.
    pub fn launch_segment(
        &self,
        cursor: &mut TranscriptSegmentCursor,
        generation: u64,
        range: Range<usize>,
        start: TranscriptSegmentStart,
    ) -> Result<(), DeviceTranscriptError> {
        cursor.validate_segment(&self.schedule, generation, &range, start)?;
        if start == TranscriptSegmentStart::Initialize {
            self.launch_initialization()?;
        }
        self.launch_operation_range(range.clone())?;
        cursor.admit_segment(&self.schedule, generation, range, start)
    }

    fn launch_initialization(&self) -> Result<(), DeviceTranscriptError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        let seed_snapshot = self
            .seed
            .map_or(core::ptr::null_mut(), |_| self.input_snapshots.as_u32_ptr());
        let code = unsafe {
            stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_init_on(
                self.state.as_u32_ptr(),
                self.seed
                    .map_or(core::ptr::null(), |slice| slice.as_u32_ptr().cast_const()),
                seed_snapshot,
                self.schedule.initial_chain(),
                stream,
            )
        };
        check_cuda("blake2s_transcript_init", code)?;
        Ok(())
    }

    fn launch_operation_range(&self, range: Range<usize>) -> Result<(), DeviceTranscriptError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        for prepared in &self.operations[range] {
            let boundary = offset_ptr(
                self.boundary_snapshots,
                prepared.operation_index as usize * BLAKE2S_TRANSCRIPT_STATE_WORDS,
            );
            let input_snapshot = offset_ptr(self.input_snapshots, prepared.input_snapshot_offset);
            let output_snapshot =
                offset_ptr(self.output_snapshots, prepared.output_snapshot_offset);
            let code = unsafe {
                match prepared.operation {
                    TranscriptOperation::MixFelts { n_felts, .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_mix_words_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            prepared.source.unwrap().as_u32_ptr().cast_const(),
                            n_felts
                                .checked_mul(4)
                                .ok_or(DeviceTranscriptError::SizeOverflow)?,
                            1,
                            input_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::MixU32s { n_words, .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_mix_words_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            prepared.source.unwrap().as_u32_ptr().cast_const(),
                            n_words,
                            0,
                            input_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::MixU64 { .. } | TranscriptOperation::AbsorbRoot { .. } => {
                        let words =
                            if matches!(prepared.operation, TranscriptOperation::MixU64 { .. }) {
                                2
                            } else {
                                8
                            };
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_mix_words_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            prepared.source.unwrap().as_u32_ptr().cast_const(),
                            words,
                            0,
                            input_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::AbsorbPowNonce { pow_bits, .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_absorb_pow_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            prepared.source.unwrap().as_u32_ptr().cast_const(),
                            pow_bits,
                            input_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::DrawSecureFelt { .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_draw_secure_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            1,
                            self.schedule.max_rejection_rounds(),
                            prepared.output.unwrap().as_u32_ptr(),
                            output_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::DrawSecureFelts { n_felts, .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_draw_secure_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            n_felts,
                            self.schedule.max_rejection_rounds(),
                            prepared.output.unwrap().as_u32_ptr(),
                            output_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::DrawU32s { .. } => {
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_draw_u32s_on(
                            self.state.as_u32_ptr(),
                            prepared.operation_index,
                            prepared.chain_before,
                            prepared.chain_after,
                            prepared.output.unwrap().as_u32_ptr(),
                            output_snapshot,
                            boundary,
                            stream,
                        )
                    }
                    TranscriptOperation::DrawQueries {
                        log_domain_size,
                        n_queries,
                        ..
                    } => stwo_backend_cuda_kernels::raw::stwo_blake2s_transcript_draw_queries_on(
                        self.state.as_u32_ptr(),
                        prepared.operation_index,
                        prepared.chain_before,
                        prepared.chain_after,
                        log_domain_size,
                        n_queries,
                        prepared.output.unwrap().as_u32_ptr(),
                        output_snapshot,
                        boundary,
                        stream,
                    ),
                }
            };
            check_cuda("blake2s_transcript_operation", code)?;
        }
        Ok(())
    }

    /// Migration soundness gate. Copies only the compact mirror snapshots after
    /// the graph segment, synchronizes once, and checks every boundary against
    /// the canonical host channel. No proof may use device challenges as
    /// authoritative before this returns `Ok`.
    pub fn verify_mirror(&self) -> Result<TranscriptMirrorReport, DeviceTranscriptError> {
        let requirements = self.schedule.requirements();
        let mut boundary_words = vec![0u32; requirements.boundary_snapshot_words];
        let mut input_words = vec![0u32; requirements.input_snapshot_used_words];
        let mut output_words = vec![0u32; requirements.output_snapshot_used_words];
        unsafe {
            self.arena.context().memcpy_d2h_async(
                boundary_words.as_mut_ptr().cast::<c_void>(),
                self.boundary_snapshots.as_void_ptr().cast_const(),
                boundary_words.len() * WORD_BYTES,
            )?;
            if !input_words.is_empty() {
                self.arena.context().memcpy_d2h_async(
                    input_words.as_mut_ptr().cast::<c_void>(),
                    self.input_snapshots.as_void_ptr().cast_const(),
                    input_words.len() * WORD_BYTES,
                )?;
            }
            if !output_words.is_empty() {
                self.arena.context().memcpy_d2h_async(
                    output_words.as_mut_ptr().cast::<c_void>(),
                    self.output_snapshots.as_void_ptr().cast_const(),
                    output_words.len() * WORD_BYTES,
                )?;
            }
        }
        self.arena.context().sync()?;

        // Inspect the device fail-closed flag before replaying untrusted seed
        // metadata or interpreting challenge snapshots.
        for (index, operation) in self.schedule.operations().iter().enumerate() {
            let raw = &boundary_words[index * BLAKE2S_TRANSCRIPT_STATE_WORDS
                ..(index + 1) * BLAKE2S_TRANSCRIPT_STATE_WORDS];
            let status = raw[10];
            if status != 0 {
                return Err(DeviceTranscriptError::DeviceStatus {
                    boundary: operation.boundary(),
                    status,
                });
            }
        }
        let reference = replay_blake2s_reference(&self.schedule, &input_words)?;
        if reference.output_words != output_words {
            return Err(DeviceTranscriptError::OutputDivergence);
        }
        for (index, expected) in reference.boundaries.iter().enumerate() {
            let raw = &boundary_words[index * BLAKE2S_TRANSCRIPT_STATE_WORDS
                ..(index + 1) * BLAKE2S_TRANSCRIPT_STATE_WORDS];
            if raw[9] != expected.cursor {
                return Err(DeviceTranscriptError::OperationOrderDivergence {
                    boundary: expected.boundary,
                    expected_cursor: expected.cursor,
                    actual_cursor: raw[9],
                });
            }
            let actual_chain = u64::from(raw[12]) | (u64::from(raw[13]) << 32);
            if actual_chain != expected.chain {
                return Err(DeviceTranscriptError::OperationChainDivergence {
                    boundary: expected.boundary,
                    expected_chain: expected.chain,
                    actual_chain,
                });
            }
            if words_to_hash(&raw[..8]) != expected.digest {
                return Err(DeviceTranscriptError::DigestDivergence(expected.boundary));
            }
            if raw[8] != expected.n_draws {
                return Err(DeviceTranscriptError::DrawCounterDivergence {
                    boundary: expected.boundary,
                    expected: expected.n_draws,
                    actual: raw[8],
                });
            }
        }
        let final_state = reference
            .boundaries
            .last()
            .expect("validated schedule has a boundary");
        Ok(TranscriptMirrorReport {
            protocol_key: self.schedule.protocol_key(),
            boundaries_verified: reference.boundaries.len(),
            output_words_verified: output_words.len(),
            final_digest: final_state.digest,
            final_n_draws: final_state.n_draws,
        })
    }
}

/// Replay the exact operation schedule from the per-operation input snapshot
/// stream retained by the device graph. This is public so integration tests can
/// pin protocol vectors without a CUDA runtime.
pub fn replay_blake2s_reference(
    schedule: &Blake2sTranscriptSchedule,
    input_words: &[u32],
) -> Result<TranscriptReferenceTrace, DeviceTranscriptError> {
    if input_words.len() != schedule.requirements().input_snapshot_used_words {
        return Err(DeviceTranscriptError::InputSnapshotLength {
            expected_words: schedule.requirements().input_snapshot_used_words,
            actual_words: input_words.len(),
        });
    }
    let mut offset = 0usize;
    let mut channel = Blake2sChannel::default();
    let mut n_draws = 0u32;
    if matches!(schedule.start(), TranscriptStart::DeviceState(_)) {
        let seed = &input_words[..SEED_WORDS];
        if seed[8] > MAX_SEED_DRAWS {
            return Err(DeviceTranscriptError::InvalidSeedDrawCount(seed[8]));
        }
        channel.update_digest(words_to_hash(&seed[..8]));
        for _ in 0..seed[8] {
            channel.draw_u32s();
        }
        n_draws = seed[8];
        offset = SEED_WORDS;
    }

    let mut boundaries = Vec::with_capacity(schedule.operations().len());
    let mut output_words = Vec::with_capacity(schedule.requirements().output_snapshot_used_words);
    for (index, operation) in schedule.operations().iter().enumerate() {
        let input_len = operation.input()?.map_or(0, |(_, words)| words);
        let input = &input_words[offset..offset + input_len];
        offset += input_len;
        match *operation {
            TranscriptOperation::MixFelts { boundary, .. } => {
                if input.iter().any(|&word| word >= P) {
                    return Err(DeviceTranscriptError::InvalidFieldInput(boundary));
                }
                let felts = input
                    .chunks_exact(4)
                    .map(|words| {
                        SecureField::from_m31_array([
                            BaseField::from_u32_unchecked(words[0]),
                            BaseField::from_u32_unchecked(words[1]),
                            BaseField::from_u32_unchecked(words[2]),
                            BaseField::from_u32_unchecked(words[3]),
                        ])
                    })
                    .collect::<Vec<_>>();
                channel.mix_felts(&felts);
                n_draws = 0;
            }
            TranscriptOperation::MixU32s { .. } => {
                channel.mix_u32s(input);
                n_draws = 0;
            }
            TranscriptOperation::MixU64 { .. } => {
                channel.mix_u64(u64::from(input[0]) | (u64::from(input[1]) << 32));
                n_draws = 0;
            }
            TranscriptOperation::AbsorbRoot { .. } => {
                Blake2sMerkleChannel::mix_root(&mut channel, words_to_hash(input));
                n_draws = 0;
            }
            TranscriptOperation::AbsorbPowNonce {
                boundary, pow_bits, ..
            } => {
                let nonce = u64::from(input[0]) | (u64::from(input[1]) << 32);
                if !channel.verify_pow_nonce(pow_bits, nonce) {
                    return Err(DeviceTranscriptError::InvalidPowNonce(boundary));
                }
                channel.mix_u64(nonce);
                n_draws = 0;
            }
            TranscriptOperation::DrawSecureFelt { boundary, .. } => {
                let values = draw_secure_reference(
                    &mut channel,
                    &mut n_draws,
                    1,
                    schedule.max_rejection_rounds(),
                    boundary,
                )?;
                output_words.extend(values);
            }
            TranscriptOperation::DrawSecureFelts {
                boundary, n_felts, ..
            } => {
                let values = draw_secure_reference(
                    &mut channel,
                    &mut n_draws,
                    n_felts,
                    schedule.max_rejection_rounds(),
                    boundary,
                )?;
                output_words.extend(values);
            }
            TranscriptOperation::DrawU32s { .. } => {
                output_words.extend(channel.draw_u32s());
                n_draws += 1;
            }
            TranscriptOperation::DrawQueries {
                log_domain_size,
                n_queries,
                ..
            } => {
                let output_start = output_words.len();
                let query_count =
                    usize::try_from(n_queries).map_err(|_| DeviceTranscriptError::SizeOverflow)?;
                while output_words.len() - output_start < query_count {
                    for word in channel.draw_u32s() {
                        output_words.push(query_position(word, log_domain_size));
                        if output_words.len() - output_start == query_count {
                            break;
                        }
                    }
                    n_draws += 1;
                }
                debug_assert_eq!(
                    operation.output()?.unwrap().1,
                    usize::try_from(n_queries).unwrap()
                );
            }
        }
        boundaries.push(TranscriptBoundaryState {
            boundary: operation.boundary(),
            digest: channel.digest(),
            n_draws,
            cursor: u32::try_from(index + 1).map_err(|_| DeviceTranscriptError::SizeOverflow)?,
            chain: schedule.prefix_chains[index + 1],
        });
    }
    debug_assert_eq!(offset, input_words.len());
    Ok(TranscriptReferenceTrace {
        boundaries,
        output_words,
    })
}

fn draw_secure_reference(
    channel: &mut Blake2sChannel,
    n_draws: &mut u32,
    n_felts: u32,
    max_rejection_rounds: u32,
    boundary: TranscriptBoundaryId,
) -> Result<Vec<u32>, DeviceTranscriptError> {
    let target = checked_words(n_felts, 4)?;
    let mut output = Vec::with_capacity(target);
    while output.len() < target {
        let mut accepted = None;
        for _ in 0..max_rejection_rounds {
            let words = channel.draw_u32s();
            *n_draws += 1;
            if words.iter().all(|&word| u64::from(word) < 2 * u64::from(P)) {
                accepted = Some(words);
                break;
            }
        }
        let words = accepted.ok_or(DeviceTranscriptError::RejectionLimit(boundary))?;
        for word in words {
            output.push(if word >= P { word - P } else { word });
            if output.len() == target {
                break;
            }
        }
    }
    Ok(output)
}

fn checked_words(value: u32, factor: usize) -> Result<usize, DeviceTranscriptError> {
    if value == 0 {
        return Err(DeviceTranscriptError::ZeroLengthOperation);
    }
    let factor = u32::try_from(factor).map_err(|_| DeviceTranscriptError::SizeOverflow)?;
    let words = value
        .checked_mul(factor)
        .ok_or(DeviceTranscriptError::SizeOverflow)?;
    usize::try_from(words).map_err(|_| DeviceTranscriptError::SizeOverflow)
}

fn nonzero_words(value: u32) -> Result<usize, DeviceTranscriptError> {
    if value == 0 {
        return Err(DeviceTranscriptError::ZeroLengthOperation);
    }
    usize::try_from(value).map_err(|_| DeviceTranscriptError::SizeOverflow)
}

fn bind_slot(
    arena: &DeviceArena,
    id: ArenaSlotId,
    required_words: usize,
    alignment_words: usize,
) -> Result<ArenaSlice, DeviceTranscriptError> {
    let slice = arena.bind(id)?;
    if slice.len_words() < required_words {
        return Err(DeviceTranscriptError::SlotTooSmall {
            slot: id,
            required_words,
            actual_words: slice.len_words(),
        });
    }
    if (slice.as_u32_ptr() as usize) % (alignment_words * WORD_BYTES) != 0 {
        return Err(DeviceTranscriptError::MisalignedSlot {
            slot: id,
            alignment_words,
        });
    }
    // Pooled slots may be larger than any single logical buffer; expose only
    // the logical extent so no consumer derives sizes from the pooled surplus.
    Ok(slice.truncated(required_words))
}

fn offset_ptr(slice: ArenaSlice, offset_words: usize) -> *mut u32 {
    debug_assert!(offset_words <= slice.len_words());
    unsafe { slice.as_u32_ptr().add(offset_words) }
}

fn words_to_hash(words: &[u32]) -> Blake2sHash {
    debug_assert_eq!(words.len(), 8);
    let mut bytes = [0u8; 32];
    for (chunk, word) in bytes.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Blake2sHash(bytes)
}

fn hash_operation(hash: &mut StableHash, operation: &TranscriptOperation) {
    hash.u32(operation.boundary().0);
    match *operation {
        TranscriptOperation::MixFelts {
            source, n_felts, ..
        } => {
            hash.u32(1);
            hash.u32(source.0);
            hash.u32(n_felts);
        }
        TranscriptOperation::MixU32s {
            source, n_words, ..
        } => {
            hash.u32(2);
            hash.u32(source.0);
            hash.u32(n_words);
        }
        TranscriptOperation::MixU64 { source, .. } => {
            hash.u32(3);
            hash.u32(source.0);
        }
        TranscriptOperation::AbsorbRoot { source, .. } => {
            hash.u32(4);
            hash.u32(source.0);
        }
        TranscriptOperation::AbsorbPowNonce {
            source, pow_bits, ..
        } => {
            hash.u32(5);
            hash.u32(source.0);
            hash.u32(pow_bits);
        }
        TranscriptOperation::DrawSecureFelt { output, .. } => {
            hash.u32(6);
            hash.u32(output.0);
        }
        TranscriptOperation::DrawSecureFelts {
            output, n_felts, ..
        } => {
            hash.u32(7);
            hash.u32(output.0);
            hash.u32(n_felts);
        }
        TranscriptOperation::DrawU32s { output, .. } => {
            hash.u32(8);
            hash.u32(output.0);
        }
        TranscriptOperation::DrawQueries {
            output,
            log_domain_size,
            n_queries,
            ..
        } => {
            hash.u32(9);
            hash.u32(output.0);
            hash.u32(log_domain_size);
            hash.u32(n_queries);
        }
    }
}

#[derive(Clone, Copy)]
struct StableHash(u64);

impl StableHash {
    fn new() -> Self {
        Self(FNV_OFFSET)
    }

    fn bytes(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(FNV_PRIME);
        }
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    fn finish(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: TranscriptInputId = TranscriptInputId(1);
    const ROOT: TranscriptInputId = TranscriptInputId(2);
    const NONCE: TranscriptInputId = TranscriptInputId(3);
    const U32S: TranscriptInputId = TranscriptInputId(4);
    const U64_VALUE: TranscriptInputId = TranscriptInputId(5);
    const X: TranscriptOutputId = TranscriptOutputId(10);
    const Y: TranscriptOutputId = TranscriptOutputId(11);
    const Z: TranscriptOutputId = TranscriptOutputId(12);
    const RAW: TranscriptOutputId = TranscriptOutputId(13);

    fn boundary(value: u32) -> TranscriptBoundaryId {
        TranscriptBoundaryId(value)
    }

    fn vector_schedule() -> Blake2sTranscriptSchedule {
        Blake2sTranscriptSchedule::new(
            TranscriptStart::Default,
            vec![
                TranscriptOperation::MixFelts {
                    boundary: boundary(1),
                    source: A,
                    n_felts: 2,
                },
                TranscriptOperation::MixU32s {
                    boundary: boundary(2),
                    source: U32S,
                    n_words: 3,
                },
                TranscriptOperation::MixU64 {
                    boundary: boundary(3),
                    source: U64_VALUE,
                },
                TranscriptOperation::AbsorbRoot {
                    boundary: boundary(4),
                    source: ROOT,
                },
                TranscriptOperation::DrawSecureFelt {
                    boundary: boundary(5),
                    output: X,
                },
                TranscriptOperation::DrawSecureFelts {
                    boundary: boundary(6),
                    output: Y,
                    n_felts: 3,
                },
                TranscriptOperation::DrawU32s {
                    boundary: boundary(7),
                    output: RAW,
                },
                TranscriptOperation::AbsorbPowNonce {
                    boundary: boundary(8),
                    source: NONCE,
                    pow_bits: 0,
                },
                TranscriptOperation::DrawQueries {
                    boundary: boundary(9),
                    output: Z,
                    log_domain_size: 23,
                    n_queries: 13,
                },
            ],
            64,
        )
        .unwrap()
    }

    #[test]
    fn schedule_key_is_stable_and_semantic() {
        let schedule = vector_schedule();
        assert_eq!(schedule.protocol_tag(), BLAKE2S_TRANSCRIPT_PROTOCOL_TAG);
        assert_eq!(schedule.protocol_key(), 0x77dc_6f53_8487_dfe2);
        let mut operations = schedule.operations().to_vec();
        if let TranscriptOperation::DrawQueries { n_queries, .. } = &mut operations[8] {
            *n_queries += 1;
        }
        let changed =
            Blake2sTranscriptSchedule::new(TranscriptStart::Default, operations, 64).unwrap();
        assert_ne!(schedule.protocol_key(), changed.protocol_key());
    }

    #[test]
    fn host_query_oracle_preserves_draw_order_dedups_and_masks_high_bits() {
        let words = [
            0x8000_0007,
            0x4000_0007,
            0x2000_0003,
            0x1000_0007,
            0x0800_0003,
        ];
        let raw = words.map(|word| query_position(word, 3));
        assert_eq!(raw, [7, 7, 3, 7, 3]);
        assert_eq!(
            BTreeSet::from_iter(raw).into_iter().collect::<Vec<_>>(),
            [3, 7]
        );
        assert_eq!(query_position(u32::MAX, 0), 0);
    }

    #[test]
    fn reference_replay_covers_every_channel_operation_boundary() {
        let schedule = vector_schedule();
        let mut inputs = vec![1, 2, 3, 4, 5, 6, 7, 8];
        inputs.extend([9, 10, 11]);
        inputs.extend([0xcafe_babe, 0x1234_5678]);
        inputs.extend(0x1020_3040u32..0x1020_3048);
        inputs.extend([0x5566_7788, 0x1122_3344]);
        let trace = replay_blake2s_reference(&schedule, &inputs).unwrap();
        assert_eq!(trace.boundaries.len(), 9);
        assert_eq!(trace.output_words.len(), 4 + 12 + 8 + 13);
        assert_eq!(trace.boundaries[4].n_draws, 1);
        assert_eq!(trace.boundaries[5].n_draws, 3);
        assert_eq!(trace.boundaries[6].n_draws, 4);
        assert_eq!(trace.boundaries[7].n_draws, 0);
        assert_eq!(trace.boundaries[8].n_draws, 2);
        assert_eq!(
            trace.boundaries.last().unwrap().digest.0,
            [
                0x22, 0x4a, 0xbf, 0x4e, 0x77, 0x35, 0xca, 0x0b, 0xc8, 0x6c, 0x45, 0x26, 0x28, 0x7e,
                0xd1, 0xaa, 0xf0, 0x24, 0xd2, 0x57, 0x2b, 0x7c, 0x61, 0x20, 0xad, 0x60, 0x3c, 0x1e,
                0x19, 0x37, 0x84, 0xdf,
            ]
        );
    }

    #[test]
    fn requirements_are_exact_and_workspace_slots_must_be_distinct() {
        let schedule = vector_schedule();
        let requirements = schedule.requirements();
        assert_eq!(requirements.state_words, 16);
        assert_eq!(requirements.boundary_snapshot_words, 9 * 16);
        assert_eq!(requirements.input_snapshot_used_words, 8 + 3 + 2 + 8 + 2);
        assert_eq!(requirements.output_snapshot_used_words, 4 + 12 + 8 + 13);
        let slots = Blake2sTranscriptWorkspaceSlots {
            state: ArenaSlotId(1),
            boundary_snapshots: ArenaSlotId(2),
            input_snapshots: ArenaSlotId(3),
            output_snapshots: ArenaSlotId(4),
        };
        assert_eq!(
            requirements.arena_slot_requirements(slots).unwrap().len(),
            4
        );
        assert!(matches!(
            requirements.arena_slot_requirements(Blake2sTranscriptWorkspaceSlots {
                output_snapshots: ArenaSlotId(3),
                ..slots
            }),
            Err(DeviceTranscriptError::DuplicateWorkspaceSlot(ArenaSlotId(
                3
            )))
        ));
    }

    #[test]
    fn device_state_seed_preserves_draw_counter_across_segments() {
        let first = Blake2sTranscriptSchedule::new(
            TranscriptStart::Default,
            vec![
                TranscriptOperation::MixU32s {
                    boundary: boundary(1),
                    source: A,
                    n_words: 3,
                },
                TranscriptOperation::DrawU32s {
                    boundary: boundary(2),
                    output: X,
                },
            ],
            64,
        )
        .unwrap();
        let first_trace = replay_blake2s_reference(&first, &[17, 18, 19]).unwrap();
        let first_final = first_trace.boundaries.last().unwrap();
        let mut seed = first_final
            .digest
            .0
            .chunks_exact(4)
            .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))
            .collect::<Vec<_>>();
        seed.push(first_final.n_draws);

        let second = Blake2sTranscriptSchedule::new(
            TranscriptStart::DeviceState(TranscriptInputId(99)),
            vec![TranscriptOperation::DrawU32s {
                boundary: boundary(3),
                output: Y,
            }],
            64,
        )
        .unwrap();
        let second_trace = replay_blake2s_reference(&second, &seed).unwrap();

        let combined = Blake2sTranscriptSchedule::new(
            TranscriptStart::Default,
            vec![
                TranscriptOperation::MixU32s {
                    boundary: boundary(1),
                    source: A,
                    n_words: 3,
                },
                TranscriptOperation::DrawU32s {
                    boundary: boundary(2),
                    output: X,
                },
                TranscriptOperation::DrawU32s {
                    boundary: boundary(3),
                    output: Y,
                },
            ],
            64,
        )
        .unwrap();
        let combined_trace = replay_blake2s_reference(&combined, &[17, 18, 19]).unwrap();
        assert_eq!(second_trace.output_words, combined_trace.output_words[8..]);
        assert_eq!(
            second_trace.boundaries[0].digest,
            combined_trace.boundaries[2].digest
        );
        assert_eq!(
            second_trace.boundaries[0].n_draws,
            combined_trace.boundaries[2].n_draws
        );
    }

    #[test]
    fn segment_cursor_requires_contiguous_order_and_fresh_generation() {
        let schedule = vector_schedule();
        let mut cursor = TranscriptSegmentCursor::new(&schedule);
        cursor.begin_generation(7).unwrap();
        cursor
            .admit_segment(&schedule, 7, 0..3, TranscriptSegmentStart::Initialize)
            .unwrap();
        assert_eq!(cursor.next_operation(), 3);

        assert!(matches!(
            cursor.admit_segment(&schedule, 7, 4..6, TranscriptSegmentStart::Resume),
            Err(DeviceTranscriptError::OutOfOrderSegment {
                expected_start: 3,
                actual_start: 4
            })
        ));
        assert!(matches!(
            cursor.admit_segment(&schedule, 6, 3..6, TranscriptSegmentStart::Resume),
            Err(DeviceTranscriptError::SegmentGenerationMismatch {
                expected: 7,
                actual: 6
            })
        ));
        cursor
            .admit_segment(&schedule, 7, 3..7, TranscriptSegmentStart::Resume)
            .unwrap();
        cursor
            .admit_segment(&schedule, 7, 7..9, TranscriptSegmentStart::Resume)
            .unwrap();
        cursor.require_complete().unwrap();

        assert!(matches!(
            cursor.begin_generation(7),
            Err(DeviceTranscriptError::StaleSegmentGeneration {
                previous: 7,
                actual: 7
            })
        ));
        cursor.begin_generation(8).unwrap();
        assert!(matches!(
            cursor.admit_segment(&schedule, 8, 0..1, TranscriptSegmentStart::Resume),
            Err(DeviceTranscriptError::SegmentStartMismatch {
                expected: TranscriptSegmentStart::Initialize,
                actual: TranscriptSegmentStart::Resume
            })
        ));
    }

    #[test]
    fn segment_cursor_rejects_wrong_schedule_and_incomplete_sequence() {
        let schedule = vector_schedule();
        let mut changed_operations = schedule.operations().to_vec();
        if let TranscriptOperation::DrawQueries { n_queries, .. } = &mut changed_operations[8] {
            *n_queries += 1;
        }
        let changed =
            Blake2sTranscriptSchedule::new(TranscriptStart::Default, changed_operations, 64)
                .unwrap();
        let mut cursor = TranscriptSegmentCursor::new(&schedule);
        cursor.begin_generation(1).unwrap();
        assert!(matches!(
            cursor.admit_segment(&changed, 1, 0..1, TranscriptSegmentStart::Initialize),
            Err(DeviceTranscriptError::SegmentProtocolMismatch { .. })
        ));
        cursor
            .admit_segment(&schedule, 1, 0..2, TranscriptSegmentStart::Initialize)
            .unwrap();
        assert!(matches!(
            cursor.require_complete(),
            Err(DeviceTranscriptError::IncompleteSegmentSequence {
                next_operation: 2,
                operation_count: 9
            })
        ));
        assert!(matches!(
            cursor.admit_segment(&schedule, 1, 2..10, TranscriptSegmentStart::Resume),
            Err(DeviceTranscriptError::InvalidSegmentRange {
                start: 2,
                end: 10,
                operation_count: 9
            })
        ));
    }

    #[test]
    fn schedule_rejects_ambiguous_or_unsupported_shapes() {
        assert!(matches!(
            Blake2sTranscriptSchedule::new(TranscriptStart::Default, vec![], 64),
            Err(DeviceTranscriptError::EmptySchedule)
        ));
        assert!(matches!(
            Blake2sTranscriptSchedule::new(
                TranscriptStart::Default,
                vec![TranscriptOperation::DrawQueries {
                    boundary: boundary(1),
                    output: X,
                    log_domain_size: 32,
                    n_queries: 1,
                }],
                64,
            ),
            Err(DeviceTranscriptError::InvalidQueryDomain(32))
        ));
        assert!(matches!(
            Blake2sTranscriptSchedule::new(
                TranscriptStart::Default,
                vec![
                    TranscriptOperation::DrawU32s {
                        boundary: boundary(1),
                        output: X,
                    },
                    TranscriptOperation::DrawU32s {
                        boundary: boundary(1),
                        output: Y,
                    },
                ],
                64,
            ),
            Err(DeviceTranscriptError::DuplicateBoundary(
                TranscriptBoundaryId(1)
            ))
        ));
    }

    /// Native admission vector. On a CUDA build this covers every operation,
    /// verifies every intermediate boundary against the CPU channel, and proves
    /// eager execution and graph replay use the same launch sequence. Non-CUDA
    /// developer machines retain all pure schedule/reference tests above.
    #[test]
    fn native_device_vectors_match_reference_in_eager_and_graph_modes() {
        if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
            return;
        }

        let schedule = vector_schedule();
        let requirements = schedule.requirements().clone();
        let workspace = Blake2sTranscriptWorkspaceSlots {
            state: ArenaSlotId(1),
            boundary_snapshots: ArenaSlotId(2),
            input_snapshots: ArenaSlotId(3),
            output_snapshots: ArenaSlotId(4),
        };
        let io_specs = [
            (ArenaSlotId(10), 8usize, BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
            (ArenaSlotId(11), 8usize, BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
            (ArenaSlotId(12), 2usize, 1usize),
            (ArenaSlotId(13), 3usize, 1usize),
            (ArenaSlotId(14), 2usize, 1usize),
            (ArenaSlotId(20), 4usize, 1usize),
            (ArenaSlotId(21), 12usize, 1usize),
            (ArenaSlotId(22), 13usize, 1usize),
            (ArenaSlotId(23), 8usize, 1usize),
        ];
        let mut specs = Vec::new();
        let mut offset = 0usize;
        for requirement in requirements
            .arena_slot_requirements(workspace)
            .unwrap()
            .into_iter()
            .chain(
                io_specs
                    .into_iter()
                    .map(
                        |(id, len_words, alignment_words)| TranscriptArenaSlotRequirement {
                            id,
                            len_words,
                            alignment_words,
                        },
                    ),
            )
        {
            offset = offset.next_multiple_of(requirement.alignment_words);
            specs.push(super::super::exec_context::ArenaSlotSpec {
                id: requirement.id,
                offset_words: offset,
                len_words: requirement.len_words,
                alignment_words: requirement.alignment_words,
            });
            offset += requirement.len_words;
        }
        let layout = super::super::exec_context::ArenaLayout::new(
            offset.next_multiple_of(BLAKE2S_TRANSCRIPT_ALIGNMENT_WORDS),
            &specs,
        )
        .unwrap();
        let arena = DeviceArena::new(
            super::super::exec_context::CudaExecContext::new().unwrap(),
            layout,
        )
        .unwrap();

        let input_a = arena.bind(ArenaSlotId(10)).unwrap();
        let input_root = arena.bind(ArenaSlotId(11)).unwrap();
        let input_nonce = arena.bind(ArenaSlotId(12)).unwrap();
        let input_u32s = arena.bind(ArenaSlotId(13)).unwrap();
        let input_u64 = arena.bind(ArenaSlotId(14)).unwrap();
        let host_a = [1u32, 2, 3, 4, 5, 6, 7, 8];
        let host_root = [
            0x1020_3040u32,
            0x1020_3041,
            0x1020_3042,
            0x1020_3043,
            0x1020_3044,
            0x1020_3045,
            0x1020_3046,
            0x1020_3047,
        ];
        let host_nonce = [0x5566_7788u32, 0x1122_3344];
        let host_u32s = [9u32, 10, 11];
        let host_u64 = [0xcafe_babeu32, 0x1234_5678];
        unsafe {
            arena
                .context()
                .memcpy_h2d_async(
                    input_a.as_void_ptr(),
                    host_a.as_ptr().cast::<c_void>(),
                    input_a.len_bytes(),
                )
                .unwrap();
            arena
                .context()
                .memcpy_h2d_async(
                    input_u32s.as_void_ptr(),
                    host_u32s.as_ptr().cast::<c_void>(),
                    input_u32s.len_bytes(),
                )
                .unwrap();
            arena
                .context()
                .memcpy_h2d_async(
                    input_u64.as_void_ptr(),
                    host_u64.as_ptr().cast::<c_void>(),
                    input_u64.len_bytes(),
                )
                .unwrap();
            arena
                .context()
                .memcpy_h2d_async(
                    input_root.as_void_ptr(),
                    host_root.as_ptr().cast::<c_void>(),
                    input_root.len_bytes(),
                )
                .unwrap();
            arena
                .context()
                .memcpy_h2d_async(
                    input_nonce.as_void_ptr(),
                    host_nonce.as_ptr().cast::<c_void>(),
                    input_nonce.len_bytes(),
                )
                .unwrap();
        }
        arena.context().sync().unwrap();

        let prepared = PreparedBlake2sTranscript::prepare(
            &arena,
            schedule,
            workspace,
            &[
                TranscriptInputBinding {
                    id: A,
                    slice: input_a,
                },
                TranscriptInputBinding {
                    id: ROOT,
                    slice: input_root,
                },
                TranscriptInputBinding {
                    id: NONCE,
                    slice: input_nonce,
                },
                TranscriptInputBinding {
                    id: U32S,
                    slice: input_u32s,
                },
                TranscriptInputBinding {
                    id: U64_VALUE,
                    slice: input_u64,
                },
            ],
            &[
                TranscriptOutputBinding {
                    id: X,
                    slice: arena.bind(ArenaSlotId(20)).unwrap(),
                },
                TranscriptOutputBinding {
                    id: Y,
                    slice: arena.bind(ArenaSlotId(21)).unwrap(),
                },
                TranscriptOutputBinding {
                    id: Z,
                    slice: arena.bind(ArenaSlotId(22)).unwrap(),
                },
                TranscriptOutputBinding {
                    id: RAW,
                    slice: arena.bind(ArenaSlotId(23)).unwrap(),
                },
            ],
        )
        .unwrap();

        prepared.launch().unwrap();
        let eager = prepared.verify_mirror().unwrap();
        assert_eq!(eager.boundaries_verified, 9);
        assert_eq!(eager.output_words_verified, 37);

        let mut capture_cursor = prepared.segment_cursor();
        capture_cursor.begin_generation(1).unwrap();
        let capture = arena.context().capture().unwrap();
        prepared
            .launch_segment(
                &mut capture_cursor,
                1,
                0..3,
                TranscriptSegmentStart::Initialize,
            )
            .unwrap();
        let graph0 = capture.finish().unwrap();
        let capture = arena.context().capture().unwrap();
        prepared
            .launch_segment(&mut capture_cursor, 1, 3..7, TranscriptSegmentStart::Resume)
            .unwrap();
        let graph1 = capture.finish().unwrap();
        let capture = arena.context().capture().unwrap();
        prepared
            .launch_segment(&mut capture_cursor, 1, 7..9, TranscriptSegmentStart::Resume)
            .unwrap();
        let graph2 = capture.finish().unwrap();
        capture_cursor.require_complete().unwrap();

        let mut replay_cursor = prepared.segment_cursor();
        replay_cursor.begin_generation(1).unwrap();
        for (range, start, graph) in [
            (0..3, TranscriptSegmentStart::Initialize, &graph0),
            (3..7, TranscriptSegmentStart::Resume, &graph1),
            (7..9, TranscriptSegmentStart::Resume, &graph2),
        ] {
            replay_cursor
                .admit_segment(prepared.schedule(), 1, range, start)
                .unwrap();
            graph.launch(arena.context()).unwrap();
        }
        replay_cursor.require_complete().unwrap();
        let replay = prepared.verify_mirror().unwrap();
        assert_eq!(eager, replay);
        drop((graph0, graph1, graph2));
    }
}
