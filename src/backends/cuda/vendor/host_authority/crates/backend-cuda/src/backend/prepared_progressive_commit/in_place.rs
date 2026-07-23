//! Explicit slot admission for the one-slab progressive commitment lane.

use super::*;

impl ProgressiveLeafWorkspaceRequirements {
    pub fn in_place_slab_words(&self) -> Result<usize, PreparedProgressiveCommitError> {
        self.state_ping_words
            .max(self.state_pong_words.unwrap_or(0))
            .max(self.leaf_hash_words)
            .checked_add(
                super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            )
            .ok_or(PreparedProgressiveCommitError::SizeOverflow)
    }

    pub fn arena_slot_requirements_in_place(
        &self,
        slots: &ProgressiveLeafWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedProgressiveCommitError> {
        validate_slots(self, slots)?;
        let slab = slots.state_ping;
        if slots.leaf_hashes != slab || slots.state_pong.is_some_and(|pong| pong != slab) {
            return Err(PreparedProgressiveCommitError::InvalidSlotShape);
        }
        let mut output = Vec::new();
        if let (Some(id), Some(words)) = (slots.lde_scratch, self.lde_scratch_words) {
            output.push(slot_requirement(id, words, 1));
        }
        output.push(slot_requirement(
            slab,
            self.in_place_slab_words()?,
            STATE_ALIGNMENT_WORDS,
        ));
        for (batch, batch_slots) in self.batches.iter().zip(&slots.batches) {
            output.push(slot_requirement(
                batch_slots.coefficient_ptrs,
                batch.coefficient_pointer_words,
                POINTER_WORDS,
            ));
            output.push(slot_requirement(
                batch_slots.coefficient_sizes,
                batch.coefficient_size_words,
                1,
            ));
            output.push(slot_requirement(
                batch_slots.output_ptrs,
                batch.output_pointer_words,
                POINTER_WORDS,
            ));
        }
        let mut distinct = BTreeSet::new();
        for requirement in &output {
            if !distinct.insert(requirement.id) {
                return Err(PreparedProgressiveCommitError::AliasedSlot(requirement.id));
            }
        }
        Ok(output)
    }
}

impl ProgressiveCommitWorkspaceRequirements {
    /// Admit the complete progressive-leaf and Merkle suffix as one physical
    /// slab. Only the leaf/state/Merkle-interior identity may be shared; every
    /// descriptor, retained layer, and fused-tail output stays distinct.
    pub fn arena_slot_requirements_in_place(
        &self,
        slots: &ProgressiveCommitWorkspaceSlots,
    ) -> Result<Vec<CommitArenaSlotRequirement>, PreparedProgressiveCommitError> {
        let slab = slots.leaves.state_ping;
        if slots.leaves.leaf_hashes != slab || slots.merkle.leaves != slab {
            return Err(PreparedProgressiveCommitError::GeometryMismatch);
        }

        let mut output = self
            .leaves
            .arena_slot_requirements_in_place(&slots.leaves)?;
        let merkle = self
            .merkle
            .arena_slot_requirements_in_place(&slots.merkle)?;
        let mut merged_slab = false;
        for requirement in merkle {
            if requirement.id == slab {
                let existing = output
                    .iter_mut()
                    .find(|candidate| candidate.id == slab)
                    .ok_or(PreparedProgressiveCommitError::GeometryMismatch)?;
                existing.len_words = existing.len_words.max(requirement.len_words);
                existing.alignment_words =
                    existing.alignment_words.max(requirement.alignment_words);
                merged_slab = true;
            } else if output
                .iter()
                .any(|candidate| candidate.id == requirement.id)
            {
                return Err(PreparedProgressiveCommitError::AliasedSlot(requirement.id));
            } else {
                output.push(requirement);
            }
        }
        if !merged_slab {
            return Err(PreparedProgressiveCommitError::GeometryMismatch);
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::exec_context::{ArenaLayout, ArenaSlotSpec};
    use crate::backend::progressive_commit::{
        ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
    };

    fn admit_layout(requirements: &[CommitArenaSlotRequirement]) {
        let mut offset_words = 0usize;
        let specs = requirements
            .iter()
            .map(|requirement| {
                assert!(requirement.alignment_words.is_power_of_two());
                offset_words = offset_words.next_multiple_of(requirement.alignment_words);
                let spec = ArenaSlotSpec {
                    id: requirement.id,
                    offset_words,
                    len_words: requirement.len_words,
                    alignment_words: requirement.alignment_words,
                };
                offset_words += requirement.len_words;
                spec
            })
            .collect::<Vec<_>>();
        ArenaLayout::new(offset_words, &specs).unwrap();
    }

    fn requirements() -> ProgressiveLeafWorkspaceRequirements {
        progressive_leaf_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 5],
                    retain_evaluations: false,
                }],
            },
        )
        .unwrap()
    }

    fn slots(requirements: &ProgressiveLeafWorkspaceRequirements) -> ProgressiveLeafWorkspaceSlots {
        let slab = ArenaSlotId(1);
        ProgressiveLeafWorkspaceSlots {
            lde_scratch: requirements.lde_scratch_words.map(|_| ArenaSlotId(2)),
            state_ping: slab,
            state_pong: requirements.state_pong_words.map(|_| slab),
            leaf_hashes: slab,
            batches: requirements
                .batches
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    let first = 10 + 3 * index as u32;
                    ProgressiveBatchSlots {
                        coefficient_ptrs: ArenaSlotId(first),
                        coefficient_sizes: ArenaSlotId(first + 1),
                        output_ptrs: ArenaSlotId(first + 2),
                    }
                })
                .collect(),
        }
    }

    #[test]
    fn in_place_requirements_replace_ping_pong_and_leaf_with_one_slab() {
        let requirements = requirements();
        assert!(requirements.state_pong_words.is_some());
        let slots = slots(&requirements);
        let separate_words = requirements.state_ping_words
            + requirements.state_pong_words.unwrap()
            + requirements.leaf_hash_words;
        let in_place_words = requirements.in_place_slab_words().unwrap();
        assert!(in_place_words < separate_words);
        let physical = requirements
            .arena_slot_requirements_in_place(&slots)
            .unwrap();
        assert_eq!(
            physical
                .iter()
                .filter(|requirement| requirement.id == ArenaSlotId(1))
                .count(),
            1
        );
        assert_eq!(
            physical
                .iter()
                .find(|requirement| requirement.id == ArenaSlotId(1))
                .unwrap()
                .len_words,
            in_place_words
        );
        assert_eq!(
            physical
                .iter()
                .find(|requirement| requirement.id == ArenaSlotId(1))
                .unwrap()
                .alignment_words,
            8
        );
        admit_layout(&physical);

        let mut separate_slots = slots;
        separate_slots.state_pong = Some(ArenaSlotId(3));
        separate_slots.leaf_hashes = ArenaSlotId(4);
        let separate = requirements
            .arena_slot_requirements(&separate_slots)
            .unwrap();
        admit_layout(&separate);
    }

    #[test]
    fn in_place_requirements_fail_closed_on_any_split_state_slot() {
        let requirements = requirements();
        let mut split_pong = slots(&requirements);
        split_pong.state_pong = Some(ArenaSlotId(3));
        assert!(requirements
            .arena_slot_requirements_in_place(&split_pong)
            .is_err());
        let mut split_leaf = slots(&requirements);
        split_leaf.leaf_hashes = ArenaSlotId(3);
        assert!(requirements
            .arena_slot_requirements_in_place(&split_leaf)
            .is_err());
    }

    fn combined_requirements() -> (
        CommitWorkspaceConfig,
        ProgressiveCommitWorkspaceRequirements,
        ProgressiveCommitWorkspaceSlots,
    ) {
        let config = CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 0,
        };
        let requirements = progressive_commit_workspace_requirements_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            config,
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 4, 5],
                    retain_evaluations: false,
                }],
            },
        )
        .unwrap();
        let slab = ArenaSlotId(1);
        let slots = ProgressiveCommitWorkspaceSlots {
            leaves: ProgressiveLeafWorkspaceSlots {
                lde_scratch: requirements
                    .leaves
                    .lde_scratch_words
                    .map(|_| ArenaSlotId(2)),
                state_ping: slab,
                state_pong: requirements.leaves.state_pong_words.map(|_| slab),
                leaf_hashes: slab,
                batches: requirements
                    .leaves
                    .batches
                    .iter()
                    .enumerate()
                    .map(|(index, _)| {
                        let first = 10 + 3 * index as u32;
                        ProgressiveBatchSlots {
                            coefficient_ptrs: ArenaSlotId(first),
                            coefficient_sizes: ArenaSlotId(first + 1),
                            output_ptrs: ArenaSlotId(first + 2),
                        }
                    })
                    .collect(),
            },
            merkle: MerkleFromLeavesSlots {
                leaves: slab,
                merkle_scratch: requirements.merkle.merkle_scratch_words.map(|_| slab),
                retained_layers: requirements
                    .merkle
                    .retained_layers
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ArenaSlotId(40 + index as u32))
                    .collect(),
                tail_level_ptrs: requirements
                    .merkle
                    .tail_pointer_words
                    .map(|_| ArenaSlotId(60)),
                tail_outputs: requirements
                    .merkle
                    .tail_outputs
                    .iter()
                    .enumerate()
                    .map(|(index, _)| ArenaSlotId(70 + index as u32))
                    .collect(),
            },
        };
        (config, requirements, slots)
    }

    #[test]
    fn complete_commit_has_one_slab_and_exact_physical_saving() {
        let (_, requirements, slots) = combined_requirements();
        assert!(requirements.leaves.state_pong_words.is_some());
        assert!(requirements.merkle.merkle_scratch_words.is_some());
        assert_eq!(
            requirements.leaves.state_ping_words,
            requirements
                .leaves
                .state_ping_words
                .max(requirements.leaves.state_pong_words.unwrap())
                .max(requirements.leaves.leaf_hash_words)
        );

        let physical = requirements
            .arena_slot_requirements_in_place(&slots)
            .unwrap();
        admit_layout(&physical);
        let slab = physical
            .iter()
            .filter(|requirement| requirement.id == ArenaSlotId(1))
            .collect::<Vec<_>>();
        assert_eq!(slab.len(), 1);
        assert_eq!(slab[0].alignment_words, 8);
        assert_eq!(
            slab[0].len_words,
            requirements.leaves.state_ping_words
                + super::super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        );

        let separate_commit_words = requirements.leaves.state_ping_words
            + requirements.leaves.state_pong_words.unwrap()
            + requirements.leaves.leaf_hash_words
            + requirements.merkle.merkle_scratch_words.unwrap();
        let saved_words = separate_commit_words - slab[0].len_words;
        assert_eq!(
            saved_words,
            requirements.leaves.state_pong_words.unwrap()
                + requirements.leaves.leaf_hash_words
                + requirements.merkle.merkle_scratch_words.unwrap()
                - super::super::super::progressive_commit_in_place::PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
        );
    }

    #[test]
    fn complete_commit_rejects_every_split_or_cross_role_alias() {
        let (_, requirements, slots) = combined_requirements();

        let mut split_leaf = slots.clone();
        split_leaf.merkle.leaves = ArenaSlotId(99);
        assert!(requirements
            .arena_slot_requirements_in_place(&split_leaf)
            .is_err());

        let mut split_scratch = slots.clone();
        split_scratch.merkle.merkle_scratch = Some(ArenaSlotId(99));
        assert!(requirements
            .arena_slot_requirements_in_place(&split_scratch)
            .is_err());

        let mut retained_alias = slots;
        retained_alias.merkle.retained_layers[0] = ArenaSlotId(10);
        assert!(matches!(
            requirements.arena_slot_requirements_in_place(&retained_alias),
            Err(PreparedProgressiveCommitError::AliasedSlot(ArenaSlotId(10)))
        ));
    }
}
