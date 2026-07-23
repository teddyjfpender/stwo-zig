//! One-owner direct retained LDE into compact h8 commitment state.

use super::direct_compact_terminal_fused::PreparedDirectCompactTerminalExecution;
use super::direct_retained_b2n::PreparedBatch as DirectPreparedBatch;
use super::domain_compact_binding::{
    validate_compact_slab, CompactOutputBatch, CompactStatePreparedLaunch,
};
use super::precomputed_compact_state::bind_precomputed_compact_state_launches;
use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectCompactDomainBindingError {
    Direct(DirectRetainedB2nError),
    Compact(CompactDomainBindingError),
    ProgramIdentity,
    WorkspaceAlias {
        external: ArenaSlotId,
        workspace: ArenaSlotId,
    },
    SizeOverflow,
    Terminal(DirectCompactTerminalError),
    ExpandAbsorb(DirectTerminalExpandAbsorbError),
    UnsupportedArchitecture {
        sm_major: u32,
        sm_minor: u32,
    },
}

impl core::fmt::Display for DirectCompactDomainBindingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid direct-retained compact commitment: {self:?}")
    }
}

impl std::error::Error for DirectCompactDomainBindingError {}

impl From<DirectRetainedB2nError> for DirectCompactDomainBindingError {
    fn from(value: DirectRetainedB2nError) -> Self {
        Self::Direct(value)
    }
}

impl From<CompactDomainBindingError> for DirectCompactDomainBindingError {
    fn from(value: CompactDomainBindingError) -> Self {
        Self::Compact(value)
    }
}

impl From<PreparedProgressiveCommitError> for DirectCompactDomainBindingError {
    fn from(value: PreparedProgressiveCommitError) -> Self {
        Self::Compact(value.into())
    }
}

impl From<CompactDomainProgramError> for DirectCompactDomainBindingError {
    fn from(value: CompactDomainProgramError) -> Self {
        Self::Compact(value.into())
    }
}

impl From<DirectCompactTerminalError> for DirectCompactDomainBindingError {
    fn from(value: DirectCompactTerminalError) -> Self {
        Self::Terminal(value)
    }
}

impl From<DirectTerminalExpandAbsorbError> for DirectCompactDomainBindingError {
    fn from(value: DirectTerminalExpandAbsorbError) -> Self {
        Self::ExpandAbsorb(value)
    }
}

impl From<super::super::prepared_commit::PreparedCommitError> for DirectCompactDomainBindingError {
    fn from(value: super::super::prepared_commit::PreparedCommitError) -> Self {
        Self::Compact(value.into())
    }
}

impl From<super::super::exec_context::ArenaError> for DirectCompactDomainBindingError {
    fn from(value: super::super::exec_context::ArenaError) -> Self {
        Self::Compact(value.into())
    }
}

impl From<super::super::exec_context::CudaRuntimeError> for DirectCompactDomainBindingError {
    fn from(value: super::super::exec_context::CudaRuntimeError) -> Self {
        Self::Compact(value.into())
    }
}

/// Direct retained LDE, compact h8 state, and the existing Merkle suffix. The
/// stored compact launch vector has no coefficient-backed LDE variant.
pub struct PreparedDirectCompactDomainCommitGraph<'a> {
    pub(super) direct: PreparedDirectRetainedB2nGraph<'a>,
    pub(super) leaves: PreparedDirectCompactDomainLeaves<'a>,
    pub(super) merkle: PreparedMerkleFromLeaves<'a>,
    pub(super) retained_evaluations: Vec<Option<ArenaSlice>>,
    pub(super) terminal: Option<PreparedDirectCompactTerminalExecution>,
    pub(super) expand_absorb_receipt: Option<DirectTerminalExpandAbsorbReceipt>,
}

pub(super) struct PreparedDirectCompactDomainLeaves<'a> {
    pub(super) arena: &'a DeviceArena,
    pub(super) launches: Vec<CompactStatePreparedLaunch>,
    pub(super) leaf_hashes: ArenaSlice,
    pub(super) cache_key: u64,
}

impl PreparedDirectCompactDomainLeaves<'_> {
    fn launch(&self) -> Result<(), CompactDomainBindingError> {
        for launch in &self.launches {
            launch.launch(self.arena)?;
        }
        Ok(())
    }
}

impl CompactDomainProgram {
    /// Bind exactly one direct-LDE-to-compact graph. The direct graph owns both
    /// pointer tables. Compact state reuses its output table slices verbatim and
    /// neither calls `prepare_progressive_inputs` nor uploads a pointer table.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_prepared_direct<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        direct_program: &DirectRetainedB2nProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        columns: &[DirectRetainedB2nColumn],
        inverse_twiddles: ArenaSlice,
        forward_twiddles: ArenaSlice,
    ) -> Result<PreparedDirectCompactDomainCommitGraph<'a>, DirectCompactDomainBindingError> {
        let workspace = direct_compact_domain_arena_slot_requirements(
            self,
            base,
            domain,
            direct_program,
            slots,
        )?;
        validate_external_workspace_ownership(
            arena,
            &workspace,
            columns,
            inverse_twiddles,
            forward_twiddles,
        )?;
        let requirements = base.requirements();
        let direct = PreparedDirectRetainedB2nGraph::prepare(
            arena,
            direct_program,
            slots,
            columns,
            inverse_twiddles,
            forward_twiddles,
        )?;
        let retained_evaluations = direct
            .retained_evaluations()
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<_>>();

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

        let launches = bind_direct_compact_state_launches(
            self.steps(),
            requirements,
            direct.prepared_batches(),
            &retained_evaluations,
            slab,
            scratch_pair,
        )?;
        let finalized_columns = launches.iter().find_map(|launch| match *launch {
            CompactStatePreparedLaunch::FinalizeInPlace {
                absorbed_columns, ..
            } => Some(absorbed_columns),
            _ => None,
        });
        let column_count = u32::try_from(requirements.leaves.plan.columns.len())
            .map_err(|_| CompactDomainBindingError::InvalidTail)?;
        if finalized_columns != Some(column_count) {
            return Err(CompactDomainBindingError::InvalidTail.into());
        }

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
            return Err(CompactDomainBindingError::StateSlab.into());
        }

        Ok(PreparedDirectCompactDomainCommitGraph {
            direct,
            leaves: PreparedDirectCompactDomainLeaves {
                arena,
                launches,
                leaf_hashes,
                cache_key: self.cache_key(),
            },
            merkle,
            retained_evaluations,
            terminal: None,
            expand_absorb_receipt: None,
        })
    }
}

impl PreparedDirectCompactDomainCommitGraph<'_> {
    pub fn launch(&self) -> Result<(), DirectCompactDomainBindingError> {
        if let Some(terminal) = &self.terminal {
            terminal.launch(&self.direct, self.leaves.arena)?;
        } else {
            self.direct.launch()?;
            self.leaves.launch()?;
        }
        self.merkle
            .launch()
            .map_err(CompactDomainBindingError::from)?;
        Ok(())
    }

    pub fn direct_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = DirectRetainedB2nLaunchKind> + '_ {
        self.direct.launch_sequence()
    }

    pub fn compact_leaf_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = CompactDomainPreparedLaunchKind> + '_ {
        self.leaves
            .launches
            .iter()
            .copied()
            .map(CompactStatePreparedLaunch::kind)
    }

    pub fn tail_descriptors(
        &self,
    ) -> impl Iterator<Item = (u32, CompactBlake2sTailDescriptor)> + '_ {
        self.leaves
            .launches
            .iter()
            .copied()
            .filter_map(CompactStatePreparedLaunch::tail)
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

    /// Exact per-shape traffic/launch receipt for the opt-in terminal path.
    /// `None` identifies the explicit materialized fallback graph.
    pub fn terminal_receipt(&self) -> Option<&DirectCompactTerminalReceipt> {
        self.terminal.as_ref().map(|terminal| terminal.receipt())
    }

    pub fn expand_absorb_receipt(&self) -> Option<&DirectTerminalExpandAbsorbReceipt> {
        self.expand_absorb_receipt.as_ref()
    }

    pub fn exact_lower_prefix_aliases(&self) -> usize {
        self.direct.exact_lower_prefix_aliases()
    }

    pub fn read_root_at_transcript_boundary(
        &self,
    ) -> Result<Blake2sHash, DirectCompactDomainBindingError> {
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

pub(super) fn validate_external_workspace_ownership(
    arena: &DeviceArena,
    workspace: &[CommitArenaSlotRequirement],
    columns: &[DirectRetainedB2nColumn],
    inverse_twiddles: ArenaSlice,
    forward_twiddles: ArenaSlice,
) -> Result<(), DirectCompactDomainBindingError> {
    let workspace = workspace
        .iter()
        .map(|requirement| {
            Ok((
                requirement.id,
                bind_slot(
                    arena,
                    requirement.id,
                    requirement.len_words,
                    requirement.alignment_words,
                )?,
            ))
        })
        .collect::<Result<Vec<_>, DirectCompactDomainBindingError>>()?;
    let external = columns
        .iter()
        .flat_map(|column| [column.source_evaluations, column.retained_output])
        .chain([inverse_twiddles, forward_twiddles])
        .collect::<Vec<_>>();
    let token = arena.context().identity_token();
    if let Some(slice) = external.iter().find(|slice| slice.context_token() != token) {
        return Err(DirectRetainedB2nError::ContextMismatch(slice.id()).into());
    }
    validate_external_workspace_aliases(&external, &workspace)
}

fn validate_external_workspace_aliases(
    external: &[ArenaSlice],
    workspace: &[(ArenaSlotId, ArenaSlice)],
) -> Result<(), DirectCompactDomainBindingError> {
    for &external in external {
        let external_range = slice_range(external)?;
        for &(workspace_id, workspace) in workspace {
            if workspace.id() != workspace_id {
                return Err(DirectCompactDomainBindingError::ProgramIdentity);
            }
            if external.id() == workspace_id
                || ranges_overlap(external_range, slice_range(workspace)?)
            {
                return Err(DirectCompactDomainBindingError::WorkspaceAlias {
                    external: external.id(),
                    workspace: workspace_id,
                });
            }
        }
    }
    Ok(())
}

fn slice_range(slice: ArenaSlice) -> Result<(usize, usize), DirectCompactDomainBindingError> {
    let start = slice.as_u32_ptr() as usize;
    let bytes = slice
        .len_words()
        .checked_mul(core::mem::size_of::<u32>())
        .ok_or(DirectCompactDomainBindingError::SizeOverflow)?;
    Ok((
        start,
        start
            .checked_add(bytes)
            .ok_or(DirectCompactDomainBindingError::SizeOverflow)?,
    ))
}

const fn ranges_overlap(left: (usize, usize), right: (usize, usize)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

/// The compact workspace remains layout-compatible for the first integration.
/// Direct owns coefficient-pointer/output-pointer slots; coefficient-size slots
/// are deliberately allocated but never bound or read by the composite.
pub fn direct_compact_domain_arena_slot_requirements(
    compact: &CompactDomainProgram,
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    direct: &DirectRetainedB2nProgram,
    slots: &ProgressiveCommitWorkspaceSlots,
) -> Result<Vec<CommitArenaSlotRequirement>, DirectCompactDomainBindingError> {
    compact.validate_against(base, domain)?;
    validate_direct_program(base, direct)?;
    let direct_workspace = direct.arena_slot_requirements(slots)?;
    let workspace = compact_domain_arena_slot_requirements(compact, base, domain, slots)?;
    for direct_requirement in direct_workspace {
        let mut matching = workspace
            .iter()
            .filter(|requirement| requirement.id == direct_requirement.id);
        if matching.next() != Some(&direct_requirement) || matching.next().is_some() {
            return Err(DirectCompactDomainBindingError::ProgramIdentity);
        }
    }
    Ok(workspace)
}

fn validate_direct_program(
    base: &CommitProgram,
    direct: &DirectRetainedB2nProgram,
) -> Result<(), DirectCompactDomainBindingError> {
    if direct.commit_cache_key() != base.identity().cache_key {
        return Err(DirectCompactDomainBindingError::ProgramIdentity);
    }
    let plan = &base.requirements().leaves.plan;
    if direct.batches().len() != plan.lde_batches.len() {
        return Err(DirectCompactDomainBindingError::ProgramIdentity);
    }
    let mut first_column = 0usize;
    for (batch_index, (direct_batch, batch)) in
        direct.batches().iter().zip(&plan.lde_batches).enumerate()
    {
        let batch_index = u32::try_from(batch_index)
            .map_err(|_| DirectCompactDomainBindingError::ProgramIdentity)?;
        let source_log_size = batch
            .columns
            .first()
            .and_then(|&canonical| plan.columns.get(canonical))
            .map(|column| column.coefficient_log_size)
            .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
        let end_column = first_column
            .checked_add(batch.columns.len())
            .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
        let expected_columns = (first_column..end_column).collect::<Vec<_>>();
        if direct_batch.batch_index != batch_index
            || batch.columns != expected_columns
            || direct_batch.canonical_columns != expected_columns
            || direct_batch.source_log_size != source_log_size
            || direct_batch.retained_log_size != batch.evaluation_log_size
            || direct_batch.pointer_words
                != batch
                    .columns
                    .len()
                    .checked_mul(POINTER_WORDS)
                    .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?
        {
            return Err(DirectCompactDomainBindingError::ProgramIdentity);
        }
        first_column = first_column
            .checked_add(batch.columns.len())
            .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
    }
    if first_column != plan.columns.len() {
        return Err(DirectCompactDomainBindingError::ProgramIdentity);
    }
    Ok(())
}

fn bind_direct_compact_state_launches(
    steps: &[CompactDomainStep],
    requirements: &ProgressiveCommitWorkspaceRequirements,
    prepared_batches: &[DirectPreparedBatch],
    retained_outputs: &[Option<ArenaSlice>],
    slab: ArenaSlice,
    scratch_pair: ArenaSlice,
) -> Result<Vec<CompactStatePreparedLaunch>, CompactDomainBindingError> {
    let plan = &requirements.leaves.plan;
    if prepared_batches.len() != plan.lde_batches.len() {
        return Err(CompactDomainBindingError::InvalidBatch(
            u32::try_from(prepared_batches.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut batches = Vec::with_capacity(prepared_batches.len());
    for (batch_index, (prepared, planned)) in
        prepared_batches.iter().zip(&plan.lde_batches).enumerate()
    {
        let batch_index = u32::try_from(batch_index)
            .map_err(|_| CompactDomainBindingError::InvalidBatch(u32::MAX))?;
        let first_column = planned
            .columns
            .first()
            .copied()
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let source_log_size = plan
            .columns
            .get(first_column)
            .map(|column| column.coefficient_log_size)
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let expected_pointer_words = planned
            .columns
            .len()
            .checked_mul(POINTER_WORDS)
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let end_column = first_column
            .checked_add(planned.columns.len())
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        if prepared.batch_index != batch_index
            || prepared.first_column as usize != first_column
            || planned.columns != (first_column..end_column).collect::<Vec<_>>()
            || prepared.columns as usize != planned.columns.len()
            || prepared.source_log_size != source_log_size
            || prepared.retained_log_size != planned.evaluation_log_size
            || prepared.output_pointers.len_words() != expected_pointer_words
        {
            return Err(CompactDomainBindingError::InvalidBatch(batch_index));
        }
        batches.push(CompactOutputBatch {
            output_ptrs: prepared.output_pointers,
            batch_index: prepared.batch_index,
            first_column: prepared.first_column,
            columns: prepared.columns,
            log_size: prepared.retained_log_size,
        });
    }
    bind_precomputed_compact_state_launches(
        steps,
        requirements,
        &batches,
        retained_outputs,
        slab,
        scratch_pair,
    )
}

#[cfg(test)]
#[path = "direct_compact_domain_binding_tests.rs"]
mod tests;
