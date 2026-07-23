//! Explicit single-slab binding for the progressive commitment Merkle suffix.

use super::*;

impl MerkleFromLeavesRequirements {
    pub fn arena_slot_requirements_in_place(
        &self,
        slots: &MerkleFromLeavesSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedCommitError> {
        validate_merkle_slot_shape(self, slots)?;
        if slots
            .merkle_scratch
            .is_some_and(|scratch| scratch != slots.leaves)
        {
            return Err(PreparedCommitError::DuplicateSlot(slots.leaves));
        }
        let slab_words = self
            .leaf_words
            .checked_add(
                super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            )
            .ok_or(PreparedCommitError::SizeOverflow)?;
        let mut output = vec![CommitArenaSlotRequirement {
            id: slots.leaves,
            len_words: slab_words,
            alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
        }];
        output.extend(slots.retained_layers.iter().zip(&self.retained_layers).map(
            |(&id, layer)| CommitArenaSlotRequirement {
                id,
                len_words: layer.words,
                alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
            },
        ));
        if let (Some(id), Some(words)) = (slots.tail_level_ptrs, self.tail_pointer_words) {
            output.push(CommitArenaSlotRequirement {
                id,
                len_words: words,
                alignment_words: COMMIT_POINTER_ALIGNMENT_WORDS,
            });
        }
        output.extend(
            slots
                .tail_outputs
                .iter()
                .zip(&self.tail_outputs)
                .map(|(&id, layer)| CommitArenaSlotRequirement {
                    id,
                    len_words: layer.words,
                    alignment_words: COMMIT_HASH_ALIGNMENT_WORDS,
                }),
        );
        ensure_distinct(&output.iter().map(|entry| entry.id).collect::<Vec<_>>())?;
        Ok(output)
    }
}

impl<'a> PreparedMerkleFromLeaves<'a> {
    pub fn prepare_in_place_slab(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &MerkleFromLeavesRequirements,
        slots: &MerkleFromLeavesSlots,
        scratch_pair: ArenaSlice,
    ) -> Result<Self, PreparedCommitError> {
        Self::prepare_in_place_slab_with_interior_mode(
            arena,
            config,
            requirements,
            slots,
            scratch_pair,
            false,
        )
    }

    pub(crate) fn prepare_in_place_slab_with_interior_mode(
        arena: &'a DeviceArena,
        config: CommitWorkspaceConfig,
        requirements: &MerkleFromLeavesRequirements,
        slots: &MerkleFromLeavesSlots,
        scratch_pair: ArenaSlice,
        interior_fused: bool,
    ) -> Result<Self, PreparedCommitError> {
        if config.unretained_bottom_layers == 0
            || merkle_from_leaves_requirements(config)? != *requirements
        {
            return Err(PreparedCommitError::SlotShapeMismatch {
                role: "in_place_merkle_requirements",
                expected: 1,
                actual: 0,
            });
        }
        requirements.arena_slot_requirements_in_place(slots)?;
        let leaves = bind_slot(
            arena,
            slots.leaves,
            requirements.leaf_words,
            COMMIT_HASH_ALIGNMENT_WORDS,
        )?;
        let retained: Vec<_> = slots
            .retained_layers
            .iter()
            .zip(&requirements.retained_layers)
            .map(|(&id, layer)| bind_slot(arena, id, layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect::<Result<_, _>>()?;
        let tail_outputs: Vec<_> = slots
            .tail_outputs
            .iter()
            .zip(&requirements.tail_outputs)
            .map(|(&id, layer)| bind_slot(arena, id, layer.words, COMMIT_HASH_ALIGNMENT_WORDS))
            .collect::<Result<_, _>>()?;
        let interior_outputs = requirements
            .interior
            .iter()
            .map(|(_, storage)| match *storage {
                InteriorStorage::LeafPing | InteriorStorage::ScratchPong => leaves,
                InteriorStorage::Retained(index) => retained[index],
            })
            .collect();
        let tail = if tail_outputs.is_empty() {
            None
        } else {
            let level_ptrs = bind_slot(
                arena,
                slots.tail_level_ptrs.expect("requirements have tail"),
                requirements
                    .tail_pointer_words
                    .expect("requirements have tail"),
                COMMIT_POINTER_ALIGNMENT_WORDS,
            )?;
            let pointers = tail_outputs
                .iter()
                .map(|slice| slice.as_u32_ptr() as usize)
                .collect::<Vec<_>>();
            unsafe {
                arena.context().memcpy_h2d_async(
                    level_ptrs.as_void_ptr(),
                    pointers.as_ptr().cast(),
                    core::mem::size_of_val(pointers.as_slice()),
                )?;
            }
            Some(CommitTailPlan {
                level_ptrs,
                level_outputs: tail_outputs.clone(),
            })
        };
        arena.context().sync()?;
        let plan = CommitGraphPlan::new_merkle_from_leaves_in_place_with_mode(
            config.lifting_log_size,
            config.unretained_bottom_layers,
            leaves,
            scratch_pair,
            interior_outputs,
            tail,
            interior_fused,
        )?;
        let mut retained_layers_bottom_up = retained;
        retained_layers_bottom_up.extend(tail_outputs);
        Ok(Self {
            arena,
            plan,
            leaves,
            retained_layers_bottom_up,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CommitWorkspaceConfig {
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 0,
        }
    }

    fn slots(slab: u32) -> MerkleFromLeavesSlots {
        MerkleFromLeavesSlots {
            leaves: ArenaSlotId(slab),
            merkle_scratch: Some(ArenaSlotId(slab)),
            retained_layers: vec![ArenaSlotId(2), ArenaSlotId(3), ArenaSlotId(4)],
            tail_level_ptrs: None,
            tail_outputs: Vec::new(),
        }
    }

    #[test]
    fn one_slab_replaces_leaf_and_scratch_requirements() {
        let requirements = merkle_from_leaves_requirements(config()).unwrap();
        assert!(requirements.merkle_scratch_words.is_some());
        let physical = requirements
            .arena_slot_requirements_in_place(&slots(1))
            .unwrap();
        assert_eq!(physical.len(), 4);
        assert_eq!(physical[0].id, ArenaSlotId(1));
        assert_eq!(
            physical[0].len_words,
            requirements.leaf_words
                + super::super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        );
    }

    #[test]
    fn in_place_slot_contract_rejects_split_or_retained_aliases() {
        let requirements = merkle_from_leaves_requirements(config()).unwrap();
        let mut split = slots(1);
        split.merkle_scratch = Some(ArenaSlotId(9));
        assert!(requirements
            .arena_slot_requirements_in_place(&split)
            .is_err());
        let mut retained_alias = slots(1);
        retained_alias.retained_layers[0] = ArenaSlotId(1);
        assert!(requirements
            .arena_slot_requirements_in_place(&retained_alias)
            .is_err());
    }
}
