//! Production-capable binder for mixed terminal and materialized-rise fusion.

use std::collections::BTreeSet;

use super::direct_compact_domain_binding::{
    validate_external_workspace_ownership, PreparedDirectCompactDomainLeaves,
};
use super::direct_compact_terminal_fused::PreparedDirectCompactTerminalExecution;
use super::*;
use crate::backend::exec_context::cuda_device_snapshot;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

pub type PreparedDirectTerminalExpandAbsorbGraph<'a> = PreparedDirectCompactDomainCommitGraph<'a>;

impl DirectTerminalExpandAbsorbProgram {
    /// Bind the sealed mixed executor. Preparation configures fixed16 kernels;
    /// launch performs no allocation, transfer, synchronization, or probing.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_prepared<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        compact: &CompactDomainProgram,
        fused: &FusedCompactDomainProgram,
        direct: &DirectRetainedB2nProgram,
        terminal: DirectCompactTerminalProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        columns: &[DirectRetainedB2nColumn],
        inverse_twiddles: ArenaSlice,
        forward_twiddles: ArenaSlice,
    ) -> Result<PreparedDirectTerminalExpandAbsorbGraph<'a>, DirectCompactDomainBindingError> {
        self.validate_against(base, domain, compact, fused, direct, &terminal)?;
        let snapshot = cuda_device_snapshot()?;
        if !fused_compact_domain_arch_supported(snapshot.sm_major, snapshot.sm_minor) {
            return Err(DirectCompactDomainBindingError::UnsupportedArchitecture {
                sm_major: snapshot.sm_major,
                sm_minor: snapshot.sm_minor,
            });
        }
        let workspace = direct_terminal_expand_absorb_arena_slot_requirements(
            self, base, domain, compact, fused, direct, &terminal, slots,
        )?;
        validate_external_workspace_ownership(
            arena,
            &workspace,
            columns,
            inverse_twiddles,
            forward_twiddles,
        )?;
        let direct_graph = PreparedDirectRetainedB2nGraph::prepare(
            arena,
            direct,
            slots,
            columns,
            inverse_twiddles,
            forward_twiddles,
        )?;
        direct_graph.validate_terminal_output_disjoint()?;
        let retained_evaluations = direct_graph
            .retained_evaluations()
            .iter()
            .copied()
            .map(Some)
            .collect::<Vec<_>>();

        let slab = bind_slot(
            arena,
            slots.leaves.state_ping,
            self.receipt().qualified_slab_capacity_words,
            STATE_ALIGNMENT_WORDS,
        )?;
        let scratch_offset = slab
            .len_words()
            .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
            .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
        let scratch = slab.checked_subslice(scratch_offset, PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)?;
        let leaf_hashes = slab.checked_subslice(0, base.requirements().merkle.leaf_words)?;
        validate_slab(self, domain, slab, leaf_hashes, scratch)?;

        let (execution, launches) = PreparedDirectCompactTerminalExecution::bind_expand_absorb(
            self,
            terminal,
            direct_graph.prepared_batches(),
            &base.requirements().leaves.plan,
            &retained_evaluations,
            slab,
            scratch,
        )?;
        execution.configure()?;
        let merkle = PreparedMerkleFromLeaves::prepare_in_place_slab_with_interior_mode(
            arena,
            base.identity().config,
            &base.requirements().merkle,
            &slots.merkle,
            scratch,
            base.identity().interior4_fused,
        )?;
        if merkle.leaves().id() != leaf_hashes.id()
            || merkle.leaves().as_u32_ptr() != leaf_hashes.as_u32_ptr()
        {
            return Err(DirectCompactDomainBindingError::ProgramIdentity);
        }
        Ok(PreparedDirectCompactDomainCommitGraph {
            direct: direct_graph,
            leaves: PreparedDirectCompactDomainLeaves {
                arena,
                launches,
                leaf_hashes,
                cache_key: compact.cache_key(),
            },
            merkle,
            retained_evaluations,
            terminal: Some(execution),
            expand_absorb_receipt: Some(self.receipt().clone()),
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub fn direct_terminal_expand_absorb_arena_slot_requirements(
    program: &DirectTerminalExpandAbsorbProgram,
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    compact: &CompactDomainProgram,
    fused: &FusedCompactDomainProgram,
    direct: &DirectRetainedB2nProgram,
    terminal: &DirectCompactTerminalProgram,
    slots: &ProgressiveCommitWorkspaceSlots,
) -> Result<Vec<CommitArenaSlotRequirement>, DirectCompactDomainBindingError> {
    program.validate_against(base, domain, compact, fused, direct, terminal)?;
    let workspace = base
        .requirements()
        .arena_slot_requirements_in_place(slots)?;
    let workspace_ids = workspace
        .iter()
        .map(|requirement| requirement.id)
        .collect::<BTreeSet<_>>();
    for requirement in direct.arena_slot_requirements(slots)? {
        if !workspace_ids.contains(&requirement.id)
            || workspace
                .iter()
                .filter(|candidate| candidate.id == requirement.id)
                .ne(core::iter::once(&requirement))
        {
            return Err(DirectCompactDomainBindingError::ProgramIdentity);
        }
    }
    let slab = workspace
        .iter()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
    if slab.len_words != domain.slab_words()
        || slab.len_words != program.receipt().qualified_slab_capacity_words
        || slab.alignment_words != STATE_ALIGNMENT_WORDS
    {
        return Err(DirectCompactDomainBindingError::ProgramIdentity);
    }
    Ok(workspace)
}

pub(super) fn validate_slab(
    program: &DirectTerminalExpandAbsorbProgram,
    domain: &DomainCooperativeProgram,
    slab: ArenaSlice,
    leaves: ArenaSlice,
    scratch: ArenaSlice,
) -> Result<(), DirectCompactDomainBindingError> {
    let scratch_offset = slab
        .len_words()
        .checked_sub(PROGRESSIVE_IN_PLACE_SCRATCH_WORDS)
        .ok_or(DirectCompactDomainBindingError::ProgramIdentity)?;
    if slab.len_words() != domain.slab_words()
        || slab.len_words() != program.receipt().qualified_slab_capacity_words
        || leaves.id() != slab.id()
        || leaves.as_u32_ptr() != slab.as_u32_ptr()
        || scratch.id() != slab.id()
        || scratch.len_words() != PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        || scratch.as_u32_ptr() != slab.as_u32_ptr().wrapping_add(scratch_offset)
    {
        return Err(DirectCompactDomainBindingError::ProgramIdentity);
    }
    Ok(())
}
