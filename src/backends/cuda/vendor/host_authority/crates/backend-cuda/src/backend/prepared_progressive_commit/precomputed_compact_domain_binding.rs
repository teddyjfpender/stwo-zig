//! Compact h8 commitment for evaluations produced by an exact upstream graph.
//!
//! This is the coefficient-free successor used by Composition's fused split:
//! it binds the already-materialized canonical evaluation columns, runs only
//! compact leaf state, then reuses the qualified in-place Merkle suffix.

use core::ffi::c_void;
use std::collections::BTreeSet;

use super::domain_compact_binding::{
    validate_compact_slab, CompactOutputBatch, CompactStatePreparedLaunch,
};
use super::precomputed_compact_state::bind_precomputed_compact_state_launches;
use super::*;
use crate::backend::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;

/// A coefficient-free compact commitment over canonical retained evaluations.
pub struct PreparedPrecomputedCompactDomainCommitGraph<'a> {
    arena: &'a DeviceArena,
    launches: Vec<CompactStatePreparedLaunch>,
    merkle: PreparedMerkleFromLeaves<'a>,
    retained_evaluations: Vec<Option<ArenaSlice>>,
    output_pointer_tables: Vec<ArenaSlice>,
    leaf_hashes: ArenaSlice,
    cache_key: u64,
}

impl CompactDomainProgram {
    /// Bind the exact compact successor without preparing or launching an LDE.
    /// Every LDE batch in the immutable program must map canonically onto the
    /// supplied evaluation columns and its existing output-pointer slot.
    pub fn bind_prepared_evaluations<'a>(
        &self,
        arena: &'a DeviceArena,
        base: &CommitProgram,
        domain: &DomainCooperativeProgram,
        slots: &ProgressiveCommitWorkspaceSlots,
        retained_outputs: &[Option<ArenaSlice>],
    ) -> Result<PreparedPrecomputedCompactDomainCommitGraph<'a>, CompactDomainBindingError> {
        self.validate_against(base, domain)?;
        let requirements = base.requirements();
        let workspace = compact_domain_arena_slot_requirements(self, base, domain, slots)?;
        let workspace_ids = workspace
            .iter()
            .map(|requirement| requirement.id)
            .collect::<BTreeSet<_>>();
        validate_retained_outputs(arena, requirements, retained_outputs, &workspace_ids)?;

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

        let (batches, output_pointer_tables) =
            prepare_output_batches(arena, requirements, slots, retained_outputs)?;
        let launches = bind_precomputed_compact_state_launches(
            self.steps(),
            requirements,
            &batches,
            retained_outputs,
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
            return Err(CompactDomainBindingError::InvalidTail);
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

        Ok(PreparedPrecomputedCompactDomainCommitGraph {
            arena,
            launches,
            merkle,
            retained_evaluations: retained_outputs.to_vec(),
            output_pointer_tables,
            leaf_hashes,
            cache_key: self.cache_key(),
        })
    }
}

impl PreparedPrecomputedCompactDomainCommitGraph<'_> {
    pub fn launch(&self) -> Result<(), CompactDomainBindingError> {
        for launch in &self.launches {
            launch.launch(self.arena)?;
        }
        self.merkle.launch()?;
        Ok(())
    }

    pub fn leaf_launch_sequence(
        &self,
    ) -> impl ExactSizeIterator<Item = CompactDomainPreparedLaunchKind> + '_ {
        self.launches
            .iter()
            .copied()
            .map(CompactStatePreparedLaunch::kind)
    }

    pub fn cache_key(&self) -> u64 {
        self.cache_key
    }

    pub fn leaf_hashes(&self) -> ArenaSlice {
        self.leaf_hashes
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

    pub fn output_pointer_tables(&self) -> &[ArenaSlice] {
        &self.output_pointer_tables
    }

    pub fn read_root_at_transcript_boundary(
        &self,
    ) -> Result<Blake2sHash, CompactDomainBindingError> {
        let mut root = Blake2sHash::default();
        // SAFETY: `root_slice` is a live device allocation for exactly one
        // Blake2s root and `root` provides the matching initialized host span.
        unsafe {
            self.arena.context().memcpy_d2h_async(
                root.0.as_mut_ptr().cast(),
                self.root_slice().as_void_ptr().cast_const(),
                core::mem::size_of::<Blake2sHash>(),
            )?;
        }
        self.arena.context().sync()?;
        Ok(root)
    }
}

fn validate_retained_outputs(
    arena: &DeviceArena,
    requirements: &ProgressiveCommitWorkspaceRequirements,
    retained_outputs: &[Option<ArenaSlice>],
    workspace_ids: &BTreeSet<ArenaSlotId>,
) -> Result<(), CompactDomainBindingError> {
    if retained_outputs.len() != requirements.leaves.plan.columns.len() {
        return Err(CompactDomainBindingError::InvalidRetainedOutput(
            retained_outputs.len(),
        ));
    }
    let mut ranges = Vec::with_capacity(retained_outputs.len());
    for (canonical, (output, column)) in retained_outputs
        .iter()
        .zip(&requirements.leaves.plan.columns)
        .enumerate()
    {
        let output = output.ok_or(CompactDomainBindingError::MissingTailOutput(canonical))?;
        let expected_words = 1usize
            .checked_shl(column.evaluation_log_size)
            .ok_or(CompactDomainBindingError::InvalidRetainedOutput(canonical))?;
        if !output.belongs_to(arena.context())
            || output.len_words() != expected_words
            || workspace_ids.contains(&output.id())
        {
            return Err(CompactDomainBindingError::InvalidRetainedOutput(canonical));
        }
        let start = output.as_u32_ptr() as usize;
        let end = start
            .checked_add(
                output
                    .len_words()
                    .checked_mul(core::mem::size_of::<u32>())
                    .ok_or(CompactDomainBindingError::InvalidRetainedOutput(canonical))?,
            )
            .ok_or(CompactDomainBindingError::InvalidRetainedOutput(canonical))?;
        ranges.push((canonical, output.id(), start, end));
    }
    validate_output_ranges(&ranges)
}

fn validate_output_ranges(
    ranges: &[(usize, ArenaSlotId, usize, usize)],
) -> Result<(), CompactDomainBindingError> {
    for (index, &(_, _, start, end)) in ranges.iter().enumerate() {
        for &(other_canonical, _, other_start, other_end) in &ranges[index + 1..] {
            if start < other_end && other_start < end {
                return Err(CompactDomainBindingError::InvalidRetainedOutput(
                    other_canonical,
                ));
            }
        }
    }
    Ok(())
}

fn prepare_output_batches(
    arena: &DeviceArena,
    requirements: &ProgressiveCommitWorkspaceRequirements,
    slots: &ProgressiveCommitWorkspaceSlots,
    retained_outputs: &[Option<ArenaSlice>],
) -> Result<(Vec<CompactOutputBatch>, Vec<ArenaSlice>), CompactDomainBindingError> {
    let plan = &requirements.leaves.plan;
    if slots.leaves.batches.len() != plan.lde_batches.len() {
        return Err(CompactDomainBindingError::InvalidBatch(
            u32::try_from(slots.leaves.batches.len()).unwrap_or(u32::MAX),
        ));
    }
    let mut batches = Vec::with_capacity(plan.lde_batches.len());
    let mut tables = Vec::with_capacity(plan.lde_batches.len());
    for (batch_index, (planned, batch_slots)) in plan
        .lde_batches
        .iter()
        .zip(&slots.leaves.batches)
        .enumerate()
    {
        let batch_index = u32::try_from(batch_index)
            .map_err(|_| CompactDomainBindingError::InvalidBatch(u32::MAX))?;
        let first = planned
            .columns
            .first()
            .copied()
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        let end = first
            .checked_add(planned.columns.len())
            .filter(|&end| end <= retained_outputs.len())
            .ok_or(CompactDomainBindingError::InvalidBatch(batch_index))?;
        if planned.columns != (first..end).collect::<Vec<_>>() {
            return Err(CompactDomainBindingError::InvalidBatch(batch_index));
        }
        let pointer_words = planned
            .columns
            .len()
            .checked_mul(POINTER_WORDS)
            .ok_or(CompactDomainBindingError::PointerWidth)?;
        let table = bind_slot(arena, batch_slots.output_ptrs, pointer_words, POINTER_WORDS)?;
        let addresses = retained_outputs[first..end]
            .iter()
            .enumerate()
            .map(|(offset, output)| {
                (*output)
                    .map(|output| output.as_u32_ptr() as usize)
                    .ok_or(CompactDomainBindingError::MissingTailOutput(first + offset))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let bytes = addresses
            .len()
            .checked_mul(core::mem::size_of::<usize>())
            .ok_or(CompactDomainBindingError::PointerWidth)?;
        // SAFETY: `table` was bound for one pointer-width word pair per
        // address above, while `addresses` remains alive through the sync at
        // the end of graph preparation.
        unsafe {
            arena.context().memcpy_h2d_async(
                table.as_void_ptr(),
                addresses.as_ptr().cast::<c_void>(),
                bytes,
            )?;
        }
        batches.push(CompactOutputBatch {
            output_ptrs: table,
            batch_index,
            first_column: u32::try_from(first)
                .map_err(|_| CompactDomainBindingError::InvalidBatch(batch_index))?,
            columns: u32::try_from(planned.columns.len())
                .map_err(|_| CompactDomainBindingError::InvalidBatch(batch_index))?,
            log_size: planned.evaluation_log_size,
        });
        tables.push(table);
    }
    Ok((batches, tables))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_slot_retained_subslices_must_be_disjoint() {
        let slot = ArenaSlotId(7);
        assert_eq!(
            validate_output_ranges(&[(0, slot, 0x1000, 0x1800), (1, slot, 0x1800, 0x2000)]),
            Ok(())
        );
        assert_eq!(
            validate_output_ranges(&[(0, slot, 0x1000, 0x1801), (1, slot, 0x1800, 0x2000)]),
            Err(CompactDomainBindingError::InvalidRetainedOutput(1))
        );
        assert_eq!(
            validate_output_ranges(&[
                (0, ArenaSlotId(7), 0x1000, 0x1801),
                (1, ArenaSlotId(8), 0x1800, 0x2000),
            ]),
            Err(CompactDomainBindingError::InvalidRetainedOutput(1))
        );
    }
}
