//! Address binding for the compact-h8 Mode-A program.
//!
//! This module seals every device address and launch scalar needed by the
//! native compact kernels. Launches preserve the exact program order: all LDEs,
//! compact state operations, then the qualified Merkle suffix.

pub use stwo_backend_cuda_kernels::raw::CompactBlake2sTailDescriptor;

use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

const MAX_TAIL_COLUMNS: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactDomainPreparedLaunchKind {
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
        tail_columns: u32,
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
        tail_columns: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompactDomainBindingError {
    Program(CompactDomainProgramError),
    Prepared(PreparedProgressiveCommitError),
    MissingBatch(u32),
    DuplicateBatch(u32),
    InvalidBatch(u32),
    MissingLdeReceipt(u32),
    DuplicateLdeReceipt(u32),
    MissingTailOutput(usize),
    InvalidRetainedOutput(usize),
    InvalidTail,
    InvalidCounter,
    UnsupportedLogSize(u32),
    PointerWidth,
    StateSlab,
    ScratchPair,
}

impl core::fmt::Display for CompactDomainBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid compact-h8 Mode-A CUDA binding: {self:?}")
    }
}

impl std::error::Error for CompactDomainBindingError {}

impl From<CompactDomainProgramError> for CompactDomainBindingError {
    fn from(value: CompactDomainProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<PreparedProgressiveCommitError> for CompactDomainBindingError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Prepared(value)
    }
}

impl From<super::super::prepared_commit::PreparedCommitError> for CompactDomainBindingError {
    fn from(value: super::super::prepared_commit::PreparedCommitError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Prepared(value))
    }
}

impl From<super::super::exec_context::ArenaError> for CompactDomainBindingError {
    fn from(value: super::super::exec_context::ArenaError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Arena(value))
    }
}

impl From<super::super::exec_context::CudaRuntimeError> for CompactDomainBindingError {
    fn from(value: super::super::exec_context::CudaRuntimeError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Cuda(value))
    }
}

#[derive(Clone, Copy)]
pub(super) struct CompactOutputBatch {
    pub(super) output_ptrs: ArenaSlice,
    pub(super) batch_index: u32,
    pub(super) first_column: u32,
    pub(super) columns: u32,
    pub(super) log_size: u32,
}

impl From<PreparedBatch> for CompactOutputBatch {
    fn from(batch: PreparedBatch) -> Self {
        Self {
            output_ptrs: batch.output_ptrs,
            batch_index: batch.batch_index,
            first_column: batch.absorbed_columns_before,
            columns: batch.columns,
            log_size: batch.log_size,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum CompactStatePreparedLaunch {
    Absorb {
        batch: CompactOutputBatch,
        initializes_state: bool,
        tail_columns: u32,
        tail: CompactBlake2sTailDescriptor,
        states: ArenaSlice,
    },
    ExpandInPlace {
        from_log: u32,
        to_log: u32,
        absorbed_columns: u32,
        bands: u32,
        states: ArenaSlice,
        scratch_pair: ArenaSlice,
    },
    FinalizeInPlace {
        log_size: u32,
        absorbed_columns: u32,
        tail_columns: u32,
        tail: CompactBlake2sTailDescriptor,
        states_and_hashes: ArenaSlice,
    },
}

#[derive(Clone, Copy)]
enum CompactPreparedLaunch {
    Lde(PreparedBatch),
    State(CompactStatePreparedLaunch),
}

impl CompactPreparedLaunch {
    fn kind(self) -> CompactDomainPreparedLaunchKind {
        match self {
            Self::Lde(batch) => CompactDomainPreparedLaunchKind::LdeBatch {
                batch_index: batch.batch_index,
                first_column: batch.absorbed_columns_before,
                columns: batch.columns,
                log_size: batch.log_size,
            },
            Self::State(state) => state.kind(),
        }
    }

    fn tail(self) -> Option<(u32, CompactBlake2sTailDescriptor)> {
        match self {
            Self::Lde(_) => None,
            Self::State(state) => state.tail(),
        }
    }
}

impl CompactStatePreparedLaunch {
    pub(super) fn kind(self) -> CompactDomainPreparedLaunchKind {
        match self {
            Self::Absorb {
                batch,
                initializes_state,
                tail_columns,
                ..
            } => CompactDomainPreparedLaunchKind::AbsorbDomainBatch {
                batch_index: batch.batch_index,
                first_column: batch.first_column,
                columns: batch.columns,
                log_size: batch.log_size,
                absorbed_columns_before: batch.first_column,
                initializes_state,
                tail_columns,
            },
            Self::ExpandInPlace {
                from_log,
                to_log,
                absorbed_columns,
                bands,
                ..
            } => CompactDomainPreparedLaunchKind::StateExpandInPlace {
                from_log_size: from_log,
                to_log_size: to_log,
                absorbed_columns,
                bands,
            },
            Self::FinalizeInPlace {
                log_size,
                absorbed_columns,
                tail_columns,
                ..
            } => CompactDomainPreparedLaunchKind::FinalizeInPlace {
                log_size,
                absorbed_columns,
                tail_columns,
            },
        }
    }

    pub(super) fn tail(self) -> Option<(u32, CompactBlake2sTailDescriptor)> {
        match self {
            Self::Absorb {
                tail_columns, tail, ..
            }
            | Self::FinalizeInPlace {
                tail_columns, tail, ..
            } => Some((tail_columns, tail)),
            Self::ExpandInPlace { .. } => None,
        }
    }

    pub(super) fn launch(self, arena: &DeviceArena) -> Result<(), CompactDomainBindingError> {
        let stream = arena.context().stream_raw().as_ptr();
        let (operation, code) = unsafe {
            match self {
                Self::Absorb {
                    batch,
                    initializes_state,
                    tail,
                    states,
                    ..
                } => {
                    if !stwo_backend_cuda_kernels::raw::blake2s_compact_absorb_counts_valid(
                        batch.columns,
                        batch.first_column,
                        initializes_state,
                    ) {
                        return Err(CompactDomainBindingError::InvalidCounter);
                    }
                    (
                        "compact_progressive_leaf_absorb",
                        stwo_backend_cuda_kernels::raw::stwo_blake2s_compact_absorb_quad_on(
                            1u32.checked_shl(batch.log_size).ok_or(
                                CompactDomainBindingError::UnsupportedLogSize(batch.log_size),
                            )?,
                            batch.columns,
                            batch.first_column,
                            batch.output_ptrs.as_u32_ptr().cast(),
                            u32::from(initializes_state),
                            &tail,
                            states.as_u32_ptr().cast(),
                            stream,
                        ),
                    )
                }
                Self::ExpandInPlace {
                    from_log,
                    to_log,
                    states,
                    scratch_pair,
                    ..
                } => (
                    "compact_progressive_leaf_expand_in_place",
                    stwo_backend_cuda_kernels::raw::stwo_blake2s_compact_expand_in_place_on(
                        from_log,
                        to_log,
                        states.as_u32_ptr().cast(),
                        // The qualified shared tail remains 48 words; compact
                        // expansion consumes its first 16 only.
                        scratch_pair.as_u32_ptr().cast(),
                        stream,
                    ),
                ),
                Self::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    tail,
                    states_and_hashes,
                    ..
                } => (
                    "compact_progressive_leaf_finalize_in_place",
                    stwo_backend_cuda_kernels::raw::stwo_blake2s_compact_finalize_quad_in_place_on(
                        1u32.checked_shl(log_size)
                            .ok_or(CompactDomainBindingError::UnsupportedLogSize(log_size))?,
                        absorbed_columns,
                        &tail,
                        states_and_hashes.as_u32_ptr().cast(),
                        stream,
                    ),
                ),
            }
        };
        check_cuda(operation, code)?;
        Ok(())
    }
}

/// Fully address-bound compact commitment.
pub struct PreparedCompactDomainCommitGraph<'a> {
    leaves: PreparedCompactDomainLeaves<'a>,
    merkle: PreparedMerkleFromLeaves<'a>,
    retained_evaluations: Vec<Option<ArenaSlice>>,
}

struct PreparedCompactDomainLeaves<'a> {
    arena: &'a DeviceArena,
    launches: Vec<CompactPreparedLaunch>,
    leaf_hashes: ArenaSlice,
    twiddles: ArenaSlice,
    twiddle_words: u32,
    cache_key: u64,
    ntt_leaf_fusion: ProgressiveNttLeafFusionTelemetry,
}

impl PreparedCompactDomainLeaves<'_> {
    fn launch(&self) -> Result<(), CompactDomainBindingError> {
        let stream = self.arena.context().stream_raw().as_ptr();
        for launch in &self.launches {
            match *launch {
                CompactPreparedLaunch::Lde(batch) => {
                    let code = unsafe {
                        stwo_backend_cuda_kernels::raw::stwo_lde_n2b_columns_on(
                            batch.coefficient_ptrs.as_u32_ptr().cast(),
                            batch.coefficient_sizes.as_u32_ptr(),
                            batch.output_ptrs.as_u32_ptr().cast(),
                            batch.log_size,
                            batch.columns,
                            self.twiddles.as_u32_ptr(),
                            self.twiddle_words,
                            batch
                                .log_size
                                .checked_sub(1)
                                .and_then(|log_size| 1u32.checked_shl(log_size))
                                .ok_or(CompactDomainBindingError::UnsupportedLogSize(
                                    batch.log_size,
                                ))?,
                            stream,
                        )
                    };
                    check_cuda("compact_progressive_lde_n2b", code)?;
                }
                CompactPreparedLaunch::State(state) => state.launch(self.arena)?,
            }
        }
        Ok(())
    }
}

impl CompactDomainProgram {
    /// Bind the exact compact successor. Descriptor uploads and the qualified
    /// Merkle suffix are prepared before any eager or captured launch.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_prepared<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<PreparedCompactDomainCommitGraph<'a>, CompactDomainBindingError> {
        self.validate_against(base, domain)?;
        let requirements = base.requirements();
        let workspace = compact_domain_arena_slot_requirements(self, base, domain, slots)?;
        let workspace_ids = workspace
            .iter()
            .map(|requirement| requirement.id)
            .collect::<BTreeSet<_>>();

        let slab = bind_slot(
            arena,
            slots.leaves.state_ping,
            self.slab_words(),
            HASH_WORDS,
        )?;
        let scratch_offset = self
            .slab_words()
            .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
            .ok_or(CompactDomainBindingError::StateSlab)?;
        let scratch_pair =
            slab.checked_subslice(scratch_offset, PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)?;
        let leaf_hashes = slab.checked_subslice(0, requirements.merkle.leaf_words)?;
        validate_compact_slab(self, requirements, slab, leaf_hashes, scratch_pair)?;

        let PreparedProgressiveInputs {
            batches,
            uploads,
            twiddle_words,
            fusion_telemetry,
            absorbed_columns,
        } = prepare_progressive_inputs(
            arena,
            &requirements.leaves,
            &slots.leaves,
            coefficients,
            retained_outputs,
            twiddles,
            ProgressiveNttLeafFusionMode::Separate,
            &workspace_ids,
        )?;
        let launches = bind_compact_launches(
            self,
            requirements,
            batches,
            retained_outputs,
            slab,
            scratch_pair,
        )?;
        let finalized_columns = launches.iter().find_map(|launch| match *launch {
            CompactPreparedLaunch::State(CompactStatePreparedLaunch::FinalizeInPlace {
                absorbed_columns,
                ..
            }) => Some(absorbed_columns),
            _ => None,
        });
        if finalized_columns != Some(absorbed_columns) {
            return Err(CompactDomainBindingError::InvalidTail);
        }

        for (destination, descriptor) in &uploads {
            let (source, bytes) = descriptor.bytes();
            unsafe {
                arena
                    .context()
                    .memcpy_h2d_async(destination.as_void_ptr(), source, bytes)?;
            }
        }
        arena.context().sync()?;

        let merkle = PreparedMerkleFromLeaves::prepare_in_place_slab_with_interior_mode(
            arena,
            base.identity().config,
            &requirements.merkle,
            &slots.merkle,
            scratch_pair,
            base.identity().interior4_fused,
        )?;
        if merkle.leaves().as_u32_ptr() != leaf_hashes.as_u32_ptr()
            || merkle.leaves().id() != leaf_hashes.id()
        {
            return Err(CompactDomainBindingError::StateSlab);
        }
        Ok(PreparedCompactDomainCommitGraph {
            leaves: PreparedCompactDomainLeaves {
                arena,
                launches,
                leaf_hashes,
                twiddles,
                twiddle_words,
                cache_key: self.cache_key(),
                ntt_leaf_fusion: fusion_telemetry,
            },
            merkle,
            retained_evaluations: retained_outputs.to_vec(),
        })
    }
}

impl PreparedCompactDomainCommitGraph<'_> {
    pub fn launch(&self) -> Result<(), CompactDomainBindingError> {
        self.leaves.launch()?;
        self.merkle.launch()?;
        Ok(())
    }

    pub fn leaf_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = CompactDomainPreparedLaunchKind> + '_ {
        self.leaves
            .launches
            .iter()
            .copied()
            .map(|launch| launch.kind())
    }

    pub fn tail_descriptors(
        &self,
    ) -> impl Iterator<Item = (u32, CompactBlake2sTailDescriptor)> + '_ {
        self.leaves
            .launches
            .iter()
            .copied()
            .filter_map(|launch| launch.tail())
    }

    pub fn cache_key(&self) -> u64 {
        self.leaves.cache_key
    }

    pub fn leaf_hashes(&self) -> ArenaSlice {
        self.leaves.leaf_hashes
    }

    pub fn root_slice(&self) -> ArenaSlice {
        self.merkle.root_slice()
    }

    pub fn merkle_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = super::super::commit_graph::CommitLaunchKind> + '_ {
        self.merkle.launch_sequence()
    }

    pub fn retained_layers_bottom_up(&self) -> &[ArenaSlice] {
        self.merkle.retained_layers_bottom_up()
    }

    pub fn retained_evaluations(&self) -> &[Option<ArenaSlice>] {
        &self.retained_evaluations
    }

    pub fn ntt_leaf_fusion_telemetry(&self) -> ProgressiveNttLeafFusionTelemetry {
        self.leaves.ntt_leaf_fusion
    }

    pub fn read_root_at_transcript_boundary(
        &self,
    ) -> Result<Blake2sHash, CompactDomainBindingError> {
        let mut root = Blake2sHash::default();
        unsafe {
            self.leaves.arena.context().memcpy_d2h_async(
                root.0.as_mut_ptr().cast(),
                self.root_slice().as_void_ptr().cast_const(),
                core::mem::size_of::<Blake2sHash>(),
            )?;
        }
        self.leaves.arena.context().sync()?;
        Ok(root)
    }
}

/// Derive the ordinary 96-byte-state workspace first, then narrow exactly the
/// one state/leaf/Merkle slab admitted by the compact program. No legacy
/// constructor can consume this smaller requirement.
pub fn compact_domain_arena_slot_requirements(
    compact: &CompactDomainProgram,
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    slots: &ProgressiveCommitWorkspaceSlots,
) -> Result<Vec<CommitArenaSlotRequirement>, CompactDomainBindingError> {
    compact.validate_against(base, domain)?;
    let requirements = base.requirements();
    let mut workspace = requirements.arena_slot_requirements_in_place(slots)?;
    let expected_compact_words = requirements
        .merkle
        .leaf_words
        .checked_add(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(CompactDomainBindingError::StateSlab)?;
    if expected_compact_words != compact.slab_words() {
        return Err(CompactDomainBindingError::StateSlab);
    }
    let slab = workspace
        .iter_mut()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .ok_or(CompactDomainBindingError::StateSlab)?;
    if slab.len_words != domain.slab_words() {
        return Err(CompactDomainBindingError::StateSlab);
    }
    slab.len_words = compact.slab_words();
    slab.alignment_words = HASH_WORDS;
    Ok(workspace)
}

pub(super) fn validate_compact_slab(
    compact: &CompactDomainProgram,
    requirements: &ProgressiveCommitWorkspaceRequirements,
    slab: ArenaSlice,
    leaves: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<(), CompactDomainBindingError> {
    let scratch_offset = compact
        .slab_words()
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(CompactDomainBindingError::ScratchPair)?;
    if slab.len_words() != compact.slab_words()
        || leaves.id() != slab.id()
        || leaves.as_u32_ptr() != slab.as_u32_ptr()
        || leaves.len_words() != requirements.merkle.leaf_words
    {
        return Err(CompactDomainBindingError::StateSlab);
    }
    if scratch.id() != slab.id()
        || scratch.len_words() != PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        || scratch.as_u32_ptr() != slab.as_u32_ptr().wrapping_add(scratch_offset)
    {
        return Err(CompactDomainBindingError::ScratchPair);
    }
    Ok(())
}

fn bind_compact_launches(
    compact: &CompactDomainProgram,
    requirements: &ProgressiveCommitWorkspaceRequirements,
    prepared_batches: Vec<(PreparedBatch, Vec<ProgressiveLdeSegment>)>,
    retained_outputs: &[Option<ArenaSlice>],
    slab: ArenaSlice,
    scratch_pair: ArenaSlice,
) -> Result<Vec<CompactPreparedLaunch>, CompactDomainBindingError> {
    let mut batches = std::collections::BTreeMap::new();
    for (batch, segments) in prepared_batches {
        let [segment] = segments.as_slice() else {
            return Err(CompactDomainBindingError::InvalidBatch(batch.batch_index));
        };
        if segment.offset != 0
            || segment.columns != batch.columns as usize
            || segment.kind != ProgressiveLdeSegmentKind::Separate
        {
            return Err(CompactDomainBindingError::InvalidBatch(batch.batch_index));
        }
        if batches.insert(batch.batch_index, batch).is_some() {
            return Err(CompactDomainBindingError::DuplicateBatch(batch.batch_index));
        }
    }

    let mut launches = Vec::with_capacity(compact.steps().len());
    for step in compact.steps() {
        let launch = match step.operation {
            CompactDomainOperation::LdeBatch {
                batch_index,
                first_column,
                columns,
                log_size,
            } => {
                let batch = exact_batch(&batches, batch_index, first_column, columns, log_size)?;
                CompactPreparedLaunch::Lde(batch)
            }
            CompactDomainOperation::AbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                log_size,
                initializes_state,
                reconstructed_tail,
                ..
            } => {
                let batch = exact_batch(&batches, batch_index, first_column, columns, log_size)?;
                let (tail_columns, tail) = bind_tail_descriptor(
                    reconstructed_tail,
                    log_size,
                    batch.absorbed_columns_before,
                    &requirements.leaves.plan,
                    retained_outputs,
                )?;
                CompactPreparedLaunch::State(CompactStatePreparedLaunch::Absorb {
                    batch: batch.into(),
                    initializes_state,
                    tail_columns,
                    tail,
                    states: slab,
                })
            }
            CompactDomainOperation::StateExpandInPlace {
                from_log_size,
                to_log_size,
                absorbed_columns,
                bands,
            } => CompactPreparedLaunch::State(CompactStatePreparedLaunch::ExpandInPlace {
                from_log: from_log_size,
                to_log: to_log_size,
                absorbed_columns,
                bands,
                states: slab,
                scratch_pair,
            }),
            CompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                reconstructed_tail,
                ..
            } => {
                let (tail_columns, tail) = bind_tail_descriptor(
                    Some(reconstructed_tail),
                    log_size,
                    absorbed_columns,
                    &requirements.leaves.plan,
                    retained_outputs,
                )?;
                CompactPreparedLaunch::State(CompactStatePreparedLaunch::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    tail_columns,
                    tail,
                    states_and_hashes: slab,
                })
            }
        };
        launches.push(launch);
    }
    Ok(launches)
}

fn exact_batch(
    batches: &std::collections::BTreeMap<u32, PreparedBatch>,
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<PreparedBatch, CompactDomainBindingError> {
    let batch = *batches
        .get(&batch_index)
        .ok_or(CompactDomainBindingError::MissingBatch(batch_index))?;
    if batch.absorbed_columns_before != first_column
        || batch.columns != columns
        || batch.log_size != log_size
    {
        return Err(CompactDomainBindingError::InvalidBatch(batch_index));
    }
    Ok(batch)
}

pub(super) fn bind_tail_descriptor(
    tail: Option<CompactDomainTail>,
    target_log_size: u32,
    absorbed_columns: u32,
    plan: &ProgressiveCommitPlan,
    retained_outputs: &[Option<ArenaSlice>],
) -> Result<(u32, CompactBlake2sTailDescriptor), CompactDomainBindingError> {
    let Some(tail) = tail else {
        let descriptor = CompactBlake2sTailDescriptor::default();
        if !stwo_backend_cuda_kernels::raw::blake2s_compact_tail_descriptor_valid(
            &descriptor,
            target_log_size,
            absorbed_columns,
        ) {
            return Err(CompactDomainBindingError::InvalidTail);
        }
        return Ok((0, descriptor));
    };
    let count =
        usize::try_from(tail.columns).map_err(|_| CompactDomainBindingError::InvalidTail)?;
    let first =
        usize::try_from(tail.first_column).map_err(|_| CompactDomainBindingError::InvalidTail)?;
    let end = first
        .checked_add(count)
        .filter(|&end| end <= plan.columns.len() && end <= retained_outputs.len())
        .ok_or(CompactDomainBindingError::InvalidTail)?;
    if count == 0 || count > MAX_TAIL_COLUMNS {
        return Err(CompactDomainBindingError::InvalidTail);
    }
    if tail.columns != stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(absorbed_columns)
    {
        return Err(CompactDomainBindingError::InvalidTail);
    }
    if end != absorbed_columns as usize {
        return Err(CompactDomainBindingError::InvalidTail);
    }
    let sources = (first..end)
        .map(|canonical| {
            let output = retained_outputs[canonical]
                .ok_or(CompactDomainBindingError::MissingTailOutput(canonical))?;
            let source_log_size = plan.columns[canonical].evaluation_log_size;
            Ok((
                u64::try_from(output.as_u32_ptr() as usize)
                    .map_err(|_| CompactDomainBindingError::PointerWidth)?,
                target_log_size
                    .checked_sub(source_log_size)
                    .ok_or(CompactDomainBindingError::InvalidTail)?,
            ))
        })
        .collect::<Result<Vec<_>, CompactDomainBindingError>>()?;
    let descriptor = descriptor_from_sources(&sources)?;
    if !stwo_backend_cuda_kernels::raw::blake2s_compact_tail_descriptor_valid(
        &descriptor,
        target_log_size,
        absorbed_columns,
    ) {
        return Err(CompactDomainBindingError::InvalidTail);
    }
    Ok((tail.columns, descriptor))
}

fn descriptor_from_sources(
    sources: &[(u64, u32)],
) -> Result<CompactBlake2sTailDescriptor, CompactDomainBindingError> {
    if sources.len() > MAX_TAIL_COLUMNS {
        return Err(CompactDomainBindingError::InvalidTail);
    }
    let mut descriptor = CompactBlake2sTailDescriptor::default();
    for (index, &(device_ptr, log_ratio)) in sources.iter().enumerate() {
        if device_ptr == 0 || device_ptr & 3 != 0 || log_ratio >= 31 {
            return Err(CompactDomainBindingError::InvalidTail);
        }
        descriptor.column_addresses[index] = device_ptr;
        descriptor.log_ratios[index] = log_ratio;
    }
    Ok(descriptor)
}

#[cfg(test)]
#[path = "domain_compact_binding_tests.rs"]
mod tests;
