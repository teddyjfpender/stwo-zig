//! Native binding for the sealed compact expand/absorb program.
//!
//! The binder preserves the qualified one-slab allocation and binds every
//! state pointer from the address-free ping/pong spans. It is explicit and
//! dormant: the ordinary compact path never selects this executor.

use std::collections::{BTreeMap, BTreeSet};

use super::domain_compact_binding::{
    bind_tail_descriptor, CompactBlake2sTailDescriptor, CompactDomainBindingError,
    CompactOutputBatch, CompactStatePreparedLaunch,
};
use super::*;
use crate::backend::exec_context::cuda_device_snapshot;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

pub const FUSED_COMPACT_DOMAIN_MIN_SM_MAJOR: u32 = 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FusedCompactDomainBindingError {
    Program(FusedCompactDomainProgramError),
    Compact(CompactDomainBindingError),
    Prepared(PreparedProgressiveCommitError),
    Terminal(DirectCompactTerminalError),
    UpstreamIdentity,
    QualifiedTerminalConflict { batch_index: u32 },
    UnsupportedArchitecture { sm_major: u32, sm_minor: u32 },
    MissingBatch(u32),
    DuplicateBatch(u32),
    InvalidBatch(u32),
    MissingLdeReceipt(u32),
    DuplicateLdeReceipt(u32),
    UnsupportedLogSize(u32),
    InvalidCounter,
    StateSlab,
    StateSpan,
    SpanOverlap,
    ScratchPair,
    FinalPlacement,
    SizeOverflow,
}

impl core::fmt::Display for FusedCompactDomainBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid fused compact-domain CUDA binding: {self:?}")
    }
}

impl std::error::Error for FusedCompactDomainBindingError {}

impl From<FusedCompactDomainProgramError> for FusedCompactDomainBindingError {
    fn from(value: FusedCompactDomainProgramError) -> Self {
        Self::Program(value)
    }
}

impl From<CompactDomainBindingError> for FusedCompactDomainBindingError {
    fn from(value: CompactDomainBindingError) -> Self {
        Self::Compact(value)
    }
}

impl From<PreparedProgressiveCommitError> for FusedCompactDomainBindingError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Prepared(value)
    }
}

impl From<DirectCompactTerminalError> for FusedCompactDomainBindingError {
    fn from(value: DirectCompactTerminalError) -> Self {
        Self::Terminal(value)
    }
}

impl From<super::super::prepared_commit::PreparedCommitError> for FusedCompactDomainBindingError {
    fn from(value: super::super::prepared_commit::PreparedCommitError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Prepared(value))
    }
}

impl From<super::super::exec_context::ArenaError> for FusedCompactDomainBindingError {
    fn from(value: super::super::exec_context::ArenaError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Arena(value))
    }
}

impl From<super::super::exec_context::CudaRuntimeError> for FusedCompactDomainBindingError {
    fn from(value: super::super::exec_context::CudaRuntimeError) -> Self {
        Self::Prepared(PreparedProgressiveCommitError::Cuda(value))
    }
}

#[derive(Clone, Copy)]
enum BoundLaunch {
    Lde(PreparedBatch),
    Compact(CompactStatePreparedLaunch),
    ExpandAbsorb {
        batch: CompactOutputBatch,
        from_log_size: u32,
        to_log_size: u32,
        absorbed_columns_before: u32,
        tail_columns: u32,
        tail: CompactBlake2sTailDescriptor,
        source_state: ArenaSlice,
        destination_state: ArenaSlice,
    },
}

#[derive(Clone, Copy)]
struct PreparedLaunch {
    operation: FusedCompactDomainOperation,
    bound: BoundLaunch,
}

impl PreparedLaunch {
    fn tail(self) -> Option<(u32, CompactBlake2sTailDescriptor)> {
        match self.bound {
            BoundLaunch::Lde(_) => None,
            BoundLaunch::Compact(launch) => launch.tail(),
            BoundLaunch::ExpandAbsorb {
                tail_columns, tail, ..
            } => Some((tail_columns, tail)),
        }
    }

    fn launch(
        self,
        arena: &DeviceArena,
        twiddles: ArenaSlice,
        twiddle_words: u32,
    ) -> Result<(), FusedCompactDomainBindingError> {
        let stream = arena.context().stream_raw().as_ptr();
        match self.bound {
            BoundLaunch::Lde(batch) => {
                let half_domain = batch
                    .log_size
                    .checked_sub(1)
                    .and_then(|log_size| 1u32.checked_shl(log_size))
                    .ok_or(FusedCompactDomainBindingError::UnsupportedLogSize(
                        batch.log_size,
                    ))?;
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_lde_n2b_columns_on(
                        batch.coefficient_ptrs.as_u32_ptr().cast(),
                        batch.coefficient_sizes.as_u32_ptr(),
                        batch.output_ptrs.as_u32_ptr().cast(),
                        batch.log_size,
                        batch.columns,
                        twiddles.as_u32_ptr(),
                        twiddle_words,
                        half_domain,
                        stream,
                    )
                };
                check_cuda("fused_compact_progressive_lde_n2b", code)?;
            }
            BoundLaunch::Compact(launch) => launch.launch(arena)?,
            BoundLaunch::ExpandAbsorb {
                batch,
                from_log_size,
                to_log_size,
                absorbed_columns_before,
                tail,
                source_state,
                destination_state,
                ..
            } => {
                if !stwo_backend_cuda_kernels::raw::blake2s_compact_absorb_counts_valid(
                    batch.columns,
                    absorbed_columns_before,
                    false,
                ) {
                    return Err(FusedCompactDomainBindingError::InvalidCounter);
                }
                let code = unsafe {
                    stwo_backend_cuda_kernels::raw::stwo_blake2s_compact_expand_absorb_quad_on(
                        from_log_size,
                        to_log_size,
                        batch.columns,
                        absorbed_columns_before,
                        batch.output_ptrs.as_u32_ptr().cast(),
                        &tail,
                        source_state.as_u32_ptr().cast(),
                        destination_state.as_u32_ptr().cast(),
                        stream,
                    )
                };
                check_cuda("fused_compact_progressive_expand_absorb", code)?;
            }
        }
        Ok(())
    }
}

pub struct PreparedFusedCompactDomainCommitGraph<'a> {
    leaves: PreparedFusedCompactDomainLeaves<'a>,
    merkle: PreparedMerkleFromLeaves<'a>,
    retained_evaluations: Vec<Option<ArenaSlice>>,
}

struct PreparedFusedCompactDomainLeaves<'a> {
    arena: &'a DeviceArena,
    launches: Vec<PreparedLaunch>,
    leaf_hashes: ArenaSlice,
    twiddles: ArenaSlice,
    twiddle_words: u32,
    cache_key: u64,
    ntt_leaf_fusion: ProgressiveNttLeafFusionTelemetry,
}

impl PreparedFusedCompactDomainLeaves<'_> {
    fn launch(&self) -> Result<(), FusedCompactDomainBindingError> {
        for &launch in &self.launches {
            launch.launch(self.arena, self.twiddles, self.twiddle_words)?;
        }
        Ok(())
    }
}

impl FusedCompactDomainProgram {
    /// Bind the materialized-LDE fused successor. This deliberately rejects
    /// any shape with a qualified direct-terminal batch: production must
    /// compose that sealed optimization rather than regress it to `Separate`.
    /// Preparation may upload immutable descriptor tables; `launch` performs
    /// no allocation, transfer, or sync.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_prepared_materialized_only<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
        terminal: &DirectCompactTerminalProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        coefficients: &[CommitCoefficientColumn],
        retained_outputs: &[Option<ArenaSlice>],
        twiddles: ArenaSlice,
    ) -> Result<PreparedFusedCompactDomainCommitGraph<'a>, FusedCompactDomainBindingError> {
        self.validate_against(base, domain, compact)?;
        if direct.commit_cache_key() != base.identity().cache_key {
            return Err(FusedCompactDomainBindingError::UpstreamIdentity);
        }
        terminal.validate_against(compact, direct)?;
        fused_compact_domain_materialized_only_admission(terminal)?;
        let snapshot = cuda_device_snapshot()?;
        if !fused_compact_domain_arch_supported(snapshot.sm_major, snapshot.sm_minor) {
            return Err(FusedCompactDomainBindingError::UnsupportedArchitecture {
                sm_major: snapshot.sm_major,
                sm_minor: snapshot.sm_minor,
            });
        }
        let requirements = base.requirements();
        let workspace =
            fused_compact_domain_arena_slot_requirements(self, base, domain, compact, slots)?;
        let workspace_ids = workspace
            .iter()
            .map(|requirement| requirement.id)
            .collect::<BTreeSet<_>>();
        let slab = bind_slot(
            arena,
            slots.leaves.state_ping,
            self.receipt().qualified_slab_capacity_words,
            STATE_ALIGNMENT_WORDS,
        )?;
        let scratch = slab.checked_subslice(
            slab.len_words()
                .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
                .ok_or(FusedCompactDomainBindingError::ScratchPair)?,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )?;
        let leaf_hashes = slab.checked_subslice(0, requirements.merkle.leaf_words)?;
        validate_slab(self, domain, slab, leaf_hashes, scratch)?;

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
        let launches = bind_launches(self, requirements, batches, retained_outputs, slab, scratch)?;
        let finalized_columns = launches.iter().find_map(|launch| match launch.operation {
            FusedCompactDomainOperation::FinalizeInPlace {
                absorbed_columns, ..
            } => Some(absorbed_columns),
            _ => None,
        });
        if finalized_columns != Some(absorbed_columns) {
            return Err(FusedCompactDomainBindingError::FinalPlacement);
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
            scratch,
            base.identity().interior4_fused,
        )?;
        if merkle.leaves().as_u32_ptr() != leaf_hashes.as_u32_ptr()
            || merkle.leaves().id() != leaf_hashes.id()
        {
            return Err(FusedCompactDomainBindingError::FinalPlacement);
        }
        Ok(PreparedFusedCompactDomainCommitGraph {
            leaves: PreparedFusedCompactDomainLeaves {
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

impl PreparedFusedCompactDomainCommitGraph<'_> {
    pub fn launch(&self) -> Result<(), FusedCompactDomainBindingError> {
        self.leaves.launch()?;
        self.merkle.launch()?;
        Ok(())
    }

    pub fn leaf_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = FusedCompactDomainOperation> + '_ {
        self.leaves.launches.iter().map(|launch| launch.operation)
    }

    pub fn tail_descriptors(
        &self,
    ) -> impl Iterator<Item = (u32, CompactBlake2sTailDescriptor)> + '_ {
        self.leaves
            .launches
            .iter()
            .copied()
            .filter_map(PreparedLaunch::tail)
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
    ) -> Result<Blake2sHash, FusedCompactDomainBindingError> {
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

pub const fn fused_compact_domain_arch_supported(sm_major: u32, _sm_minor: u32) -> bool {
    sm_major >= FUSED_COMPACT_DOMAIN_MIN_SM_MAJOR
}

pub fn fused_compact_domain_materialized_only_admission(
    terminal: &DirectCompactTerminalProgram,
) -> Result<(), FusedCompactDomainBindingError> {
    if let Some(batch) = terminal
        .receipt()
        .batches
        .iter()
        .find(|batch| !matches!(batch.mode, DirectCompactTerminalBatchMode::Materialized))
    {
        return Err(FusedCompactDomainBindingError::QualifiedTerminalConflict {
            batch_index: batch.batch_index,
        });
    }
    Ok(())
}

pub fn fused_compact_domain_arena_slot_requirements(
    fused: &FusedCompactDomainProgram,
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    compact: &CompactDomainProgram,
    slots: &ProgressiveCommitWorkspaceSlots,
) -> Result<Vec<CommitArenaSlotRequirement>, FusedCompactDomainBindingError> {
    fused.validate_against(base, domain, compact)?;
    let workspace = base
        .requirements()
        .arena_slot_requirements_in_place(slots)?;
    let slab = workspace
        .iter()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .ok_or(FusedCompactDomainBindingError::StateSlab)?;
    if slab.len_words != domain.slab_words()
        || slab.len_words != fused.receipt().qualified_slab_capacity_words
        || slab.alignment_words != STATE_ALIGNMENT_WORDS
    {
        return Err(FusedCompactDomainBindingError::StateSlab);
    }
    Ok(workspace)
}

fn bind_launches(
    fused: &FusedCompactDomainProgram,
    requirements: &ProgressiveCommitWorkspaceRequirements,
    prepared_batches: Vec<(PreparedBatch, Vec<ProgressiveLdeSegment>)>,
    retained_outputs: &[Option<ArenaSlice>],
    slab: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<Vec<PreparedLaunch>, FusedCompactDomainBindingError> {
    let mut batches = BTreeMap::new();
    for (batch, segments) in prepared_batches {
        let [segment] = segments.as_slice() else {
            return Err(FusedCompactDomainBindingError::InvalidBatch(
                batch.batch_index,
            ));
        };
        if segment.offset != 0
            || segment.columns != batch.columns as usize
            || segment.kind != ProgressiveLdeSegmentKind::Separate
        {
            return Err(FusedCompactDomainBindingError::InvalidBatch(
                batch.batch_index,
            ));
        }
        if batches.insert(batch.batch_index, batch).is_some() {
            return Err(FusedCompactDomainBindingError::DuplicateBatch(
                batch.batch_index,
            ));
        }
    }

    let mut receipts = BTreeSet::new();
    let mut launches = Vec::with_capacity(fused.steps().len());
    for step in fused.steps() {
        let bound = match step.operation {
            FusedCompactDomainOperation::LdeBatch {
                batch_index,
                first_column,
                columns,
                log_size,
            } => {
                let batch = exact_batch(&batches, batch_index, first_column, columns, log_size)?;
                if !receipts.insert(batch_index) {
                    return Err(FusedCompactDomainBindingError::DuplicateLdeReceipt(
                        batch_index,
                    ));
                }
                BoundLaunch::Lde(batch)
            }
            FusedCompactDomainOperation::AbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                log_size,
                absorbed_columns_before,
                initializes_state,
                reconstructed_tail,
                state,
                ..
            } => {
                if absorbed_columns_before != first_column {
                    return Err(FusedCompactDomainBindingError::InvalidBatch(batch_index));
                }
                let batch = exact_batch(&batches, batch_index, first_column, columns, log_size)?;
                let (tail_columns, tail) = bind_tail_descriptor(
                    reconstructed_tail,
                    log_size,
                    absorbed_columns_before,
                    &requirements.leaves.plan,
                    retained_outputs,
                )?;
                BoundLaunch::Compact(CompactStatePreparedLaunch::Absorb {
                    batch: batch.into(),
                    initializes_state,
                    tail_columns,
                    tail,
                    states: bind_state(slab, state, log_size)?,
                })
            }
            FusedCompactDomainOperation::ExpandAbsorbDomainBatch {
                batch_index,
                first_column,
                columns,
                from_log_size,
                to_log_size,
                absorbed_columns_before,
                reconstructed_tail,
                source_state,
                destination_state,
                scratch: model_scratch,
                ..
            } => {
                if absorbed_columns_before != first_column {
                    return Err(FusedCompactDomainBindingError::InvalidBatch(batch_index));
                }
                let batch = exact_batch(&batches, batch_index, first_column, columns, to_log_size)?;
                let (tail_columns, tail) = bind_tail_descriptor(
                    Some(reconstructed_tail),
                    to_log_size,
                    absorbed_columns_before,
                    &requirements.leaves.plan,
                    retained_outputs,
                )?;
                let source_state = bind_state(slab, source_state, from_log_size)?;
                let destination_state = bind_state(slab, destination_state, to_log_size)?;
                let bound_scratch = bind_span(slab, model_scratch)?;
                validate_transition(source_state, destination_state, bound_scratch, scratch)?;
                BoundLaunch::ExpandAbsorb {
                    batch: batch.into(),
                    from_log_size,
                    to_log_size,
                    absorbed_columns_before,
                    tail_columns,
                    tail,
                    source_state,
                    destination_state,
                }
            }
            FusedCompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                reconstructed_tail,
                state,
                ..
            } => {
                if state.offset_words != 0 {
                    return Err(FusedCompactDomainBindingError::FinalPlacement);
                }
                let (tail_columns, tail) = bind_tail_descriptor(
                    Some(reconstructed_tail),
                    log_size,
                    absorbed_columns,
                    &requirements.leaves.plan,
                    retained_outputs,
                )?;
                BoundLaunch::Compact(CompactStatePreparedLaunch::FinalizeInPlace {
                    log_size,
                    absorbed_columns,
                    tail_columns,
                    tail,
                    states_and_hashes: bind_state(slab, state, log_size)?,
                })
            }
        };
        launches.push(PreparedLaunch {
            operation: step.operation,
            bound,
        });
    }
    if let Some(&batch_index) = batches.keys().find(|index| !receipts.contains(index)) {
        return Err(FusedCompactDomainBindingError::MissingLdeReceipt(
            batch_index,
        ));
    }
    Ok(launches)
}

fn exact_batch(
    batches: &BTreeMap<u32, PreparedBatch>,
    batch_index: u32,
    first_column: u32,
    columns: u32,
    log_size: u32,
) -> Result<PreparedBatch, FusedCompactDomainBindingError> {
    let batch = *batches
        .get(&batch_index)
        .ok_or(FusedCompactDomainBindingError::MissingBatch(batch_index))?;
    if batch.absorbed_columns_before != first_column
        || batch.columns != columns
        || batch.log_size != log_size
    {
        return Err(FusedCompactDomainBindingError::InvalidBatch(batch_index));
    }
    Ok(batch)
}

fn bind_state(
    slab: ArenaSlice,
    model: DomainCooperativeSlabSlice,
    log_size: u32,
) -> Result<ArenaSlice, FusedCompactDomainBindingError> {
    let expected = 1usize
        .checked_shl(log_size)
        .and_then(|rows| rows.checked_mul(HASH_WORDS))
        .ok_or(FusedCompactDomainBindingError::UnsupportedLogSize(log_size))?;
    if model.len_words != expected || model.offset_words % HASH_WORDS != 0 {
        return Err(FusedCompactDomainBindingError::StateSpan);
    }
    bind_span(slab, model)
}

fn bind_span(
    slab: ArenaSlice,
    model: DomainCooperativeSlabSlice,
) -> Result<ArenaSlice, FusedCompactDomainBindingError> {
    if model.len_words == 0 {
        return Err(FusedCompactDomainBindingError::StateSpan);
    }
    Ok(slab.checked_subslice(model.offset_words, model.len_words)?)
}

fn validate_transition(
    source: ArenaSlice,
    destination: ArenaSlice,
    bound_scratch: ArenaSlice,
    expected_scratch: ArenaSlice,
) -> Result<(), FusedCompactDomainBindingError> {
    if bound_scratch.id() != expected_scratch.id()
        || bound_scratch.as_u32_ptr() != expected_scratch.as_u32_ptr()
        || bound_scratch.len_words() != expected_scratch.len_words()
    {
        return Err(FusedCompactDomainBindingError::ScratchPair);
    }
    let ranges = [
        slice_range(source)?,
        slice_range(destination)?,
        slice_range(bound_scratch)?,
    ];
    if ranges[0].0 < ranges[1].1 && ranges[1].0 < ranges[0].1
        || ranges[0].0 < ranges[2].1 && ranges[2].0 < ranges[0].1
        || ranges[1].0 < ranges[2].1 && ranges[2].0 < ranges[1].1
    {
        return Err(FusedCompactDomainBindingError::SpanOverlap);
    }
    Ok(())
}

fn slice_range(slice: ArenaSlice) -> Result<(usize, usize), FusedCompactDomainBindingError> {
    let start = slice.as_u32_ptr() as usize;
    let bytes = slice
        .len_words()
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(FusedCompactDomainBindingError::SizeOverflow)?;
    Ok((
        start,
        start
            .checked_add(bytes)
            .ok_or(FusedCompactDomainBindingError::SizeOverflow)?,
    ))
}

fn validate_slab(
    fused: &FusedCompactDomainProgram,
    domain: &DomainCooperativeProgram,
    slab: ArenaSlice,
    leaves: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<(), FusedCompactDomainBindingError> {
    let receipt = fused.receipt();
    let scratch_offset = slab
        .len_words()
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(FusedCompactDomainBindingError::ScratchPair)?;
    if slab.len_words() != domain.slab_words()
        || slab.len_words() != receipt.qualified_slab_capacity_words
        || leaves.id() != slab.id()
        || leaves.as_u32_ptr() != slab.as_u32_ptr()
    {
        return Err(FusedCompactDomainBindingError::StateSlab);
    }
    if scratch.id() != slab.id()
        || scratch.len_words() != PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        || scratch.as_u32_ptr() != slab.as_u32_ptr().wrapping_add(scratch_offset)
    {
        return Err(FusedCompactDomainBindingError::ScratchPair);
    }
    Ok(())
}

#[cfg(test)]
#[path = "domain_expand_absorb_binding_tests.rs"]
mod tests;
