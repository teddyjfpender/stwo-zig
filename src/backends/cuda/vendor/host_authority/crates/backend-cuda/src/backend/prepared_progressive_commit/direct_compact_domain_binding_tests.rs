use super::*;
use crate::backend::prepared_decommit::TraceTreeRole;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn programs() -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
    DirectRetainedB2nProgram,
) {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 7,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 7,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: [vec![3; 17], vec![4; 16], vec![5; 1]].concat(),
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    (base, domain, compact, direct)
}

fn slots(requirements: &ProgressiveCommitWorkspaceRequirements) -> ProgressiveCommitWorkspaceSlots {
    let slab = ArenaSlotId(1);
    ProgressiveCommitWorkspaceSlots {
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
                .map(|(index, _)| ArenaSlotId(100 + index as u32))
                .collect(),
            tail_level_ptrs: requirements
                .merkle
                .tail_pointer_words
                .map(|_| ArenaSlotId(120)),
            tail_outputs: requirements
                .merkle
                .tail_outputs
                .iter()
                .enumerate()
                .map(|(index, _)| ArenaSlotId(130 + index as u32))
                .collect(),
        },
    }
}

fn direct_batches(direct: &DirectRetainedB2nProgram) -> Vec<DirectPreparedBatch> {
    direct
        .batches()
        .iter()
        .enumerate()
        .map(|(index, batch)| DirectPreparedBatch {
            input_pointers: ArenaSlice::dangling_for_test(
                200 + 2 * index as u32,
                batch.pointer_words,
            ),
            output_pointers: ArenaSlice::dangling_for_test(
                201 + 2 * index as u32,
                batch.pointer_words,
            ),
            batch_index: batch.batch_index,
            first_column: u32::try_from(batch.canonical_columns[0]).unwrap(),
            source_log_size: batch.source_log_size,
            retained_log_size: batch.retained_log_size,
            columns: u32::try_from(batch.canonical_columns.len()).unwrap(),
        })
        .collect()
}

fn retained_outputs(plan: &ProgressiveCommitPlan) -> Vec<Option<ArenaSlice>> {
    plan.columns
        .iter()
        .enumerate()
        .map(|(canonical, column)| {
            Some(ArenaSlice::dangling_at_for_test(
                1_000 + canonical as u32,
                10_000 + canonical * 1_024,
                1usize << column.evaluation_log_size,
            ))
        })
        .collect()
}

fn slab_pair(compact: &CompactDomainProgram) -> (ArenaSlice, ArenaSlice) {
    let slab = ArenaSlice::dangling_at_for_test(1, 50_000, compact.slab_words());
    let scratch = slab
        .checked_subslice(
            compact.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    (slab, scratch)
}

#[test]
fn direct_compact_sequence_consumes_each_lde_receipt_without_storing_one() {
    let (base, _domain, compact, direct) = programs();
    let batches = direct_batches(&direct);
    let retained = retained_outputs(&base.requirements().leaves.plan);
    let (slab, scratch) = slab_pair(&compact);
    let launches = bind_direct_compact_state_launches(
        compact.steps(),
        base.requirements(),
        &batches,
        &retained,
        slab,
        scratch,
    )
    .unwrap();

    let expected = compact
        .steps()
        .iter()
        .filter_map(|step| match step.operation {
            CompactDomainOperation::LdeBatch { .. } => None,
            operation => Some(expected_state_kind(operation)),
        })
        .collect::<Vec<_>>();
    assert_eq!(
        launches
            .iter()
            .copied()
            .map(CompactStatePreparedLaunch::kind)
            .collect::<Vec<_>>(),
        expected
    );
    assert_eq!(
        launches.len() + direct.batches().len(),
        compact.steps().len()
    );
}

#[test]
fn state_only_plan_reuses_direct_tables_and_has_no_compact_upload_surface() {
    let (base, _domain, compact, direct) = programs();
    let batches = direct_batches(&direct);
    let retained = retained_outputs(&base.requirements().leaves.plan);
    let (slab, scratch) = slab_pair(&compact);
    let launches = bind_direct_compact_state_launches(
        compact.steps(),
        base.requirements(),
        &batches,
        &retained,
        slab,
        scratch,
    )
    .unwrap();

    let mut absorbed = 0usize;
    for launch in launches {
        match launch {
            CompactStatePreparedLaunch::Absorb { batch, .. } => {
                let direct = batches
                    .iter()
                    .find(|candidate| candidate.batch_index == batch.batch_index)
                    .unwrap();
                assert_eq!(batch.output_ptrs.id(), direct.output_pointers.id());
                assert_eq!(
                    batch.output_ptrs.as_u32_ptr(),
                    direct.output_pointers.as_u32_ptr()
                );
                absorbed += 1;
            }
            CompactStatePreparedLaunch::ExpandInPlace { .. }
            | CompactStatePreparedLaunch::FinalizeInPlace { .. } => {}
        }
    }
    assert_eq!(absorbed, batches.len());
}

#[test]
fn missing_duplicate_and_drifted_lde_receipts_fail_closed() {
    let (base, _domain, compact, direct) = programs();
    let batches = direct_batches(&direct);
    let retained = retained_outputs(&base.requirements().leaves.plan);
    let (slab, scratch) = slab_pair(&compact);

    let mut missing = compact.steps().to_vec();
    missing.remove(
        missing
            .iter()
            .position(|step| matches!(step.operation, CompactDomainOperation::LdeBatch { .. }))
            .unwrap(),
    );
    assert!(matches!(
        bind_direct_compact_state_launches(
            &missing,
            base.requirements(),
            &batches,
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::MissingLdeReceipt(_))
    ));

    let mut duplicate = compact.steps().to_vec();
    let lde = *duplicate
        .iter()
        .find(|step| matches!(step.operation, CompactDomainOperation::LdeBatch { .. }))
        .unwrap();
    duplicate.insert(1, lde);
    assert!(matches!(
        bind_direct_compact_state_launches(
            &duplicate,
            base.requirements(),
            &batches,
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::DuplicateLdeReceipt(_))
    ));

    let mut drifted = batches;
    drifted[0].retained_log_size += 1;
    assert!(matches!(
        bind_direct_compact_state_launches(
            compact.steps(),
            base.requirements(),
            &drifted,
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::InvalidBatch(0))
    ));
}

#[test]
fn every_canonical_retained_output_is_required_at_exact_extent() {
    let (base, _domain, compact, direct) = programs();
    let batches = direct_batches(&direct);
    let mut retained = retained_outputs(&base.requirements().leaves.plan);
    let (slab, scratch) = slab_pair(&compact);
    retained[0] = None;
    assert!(matches!(
        bind_direct_compact_state_launches(
            compact.steps(),
            base.requirements(),
            &batches,
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::MissingTailOutput(0))
    ));

    let mut retained = retained_outputs(&base.requirements().leaves.plan);
    retained[0] = Some(ArenaSlice::dangling_for_test(999, 1));
    assert!(matches!(
        bind_direct_compact_state_launches(
            compact.steps(),
            base.requirements(),
            &batches,
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::InvalidRetainedOutput(0))
    ));
}

#[test]
fn direct_workspace_reuses_pointer_slots_and_leaves_only_size_tables_idle() {
    let (base, domain, compact, direct) = programs();
    let slots = slots(base.requirements());
    let workspace =
        direct_compact_domain_arena_slot_requirements(&compact, &base, &domain, &direct, &slots)
            .unwrap();
    let direct_requirements = direct.arena_slot_requirements(&slots).unwrap();

    for direct in &direct_requirements {
        let matching = workspace
            .iter()
            .filter(|candidate| candidate.id == direct.id)
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 1);
        assert_eq!(matching[0].len_words, direct.len_words);
        assert_eq!(matching[0].alignment_words, direct.alignment_words);
    }
    for batch in &slots.leaves.batches {
        assert!(workspace
            .iter()
            .any(|requirement| requirement.id == batch.coefficient_sizes));
        assert!(direct_requirements
            .iter()
            .all(|requirement| requirement.id != batch.coefficient_sizes));
    }
}

#[test]
fn direct_workspace_rejects_commit_identity_and_pointer_alias_drift() {
    let (base, domain, compact, direct) = programs();
    let slots = slots(base.requirements());
    let drifted_base = CommitProgram::compile(
        CommitWorkspaceConfig {
            max_fused_tail_levels: 1,
            ..base.identity().config
        },
        base.requirements().leaves.plan.geometry.clone(),
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    assert!(matches!(
        direct_compact_domain_arena_slot_requirements(
            &compact,
            &drifted_base,
            &domain,
            &direct,
            &slots,
        ),
        Err(DirectCompactDomainBindingError::Compact(_))
            | Err(DirectCompactDomainBindingError::ProgramIdentity)
    ));

    let mut aliased = slots;
    aliased.leaves.batches[1].coefficient_ptrs = aliased.leaves.batches[0].output_ptrs;
    assert!(matches!(
        direct_compact_domain_arena_slot_requirements(&compact, &base, &domain, &direct, &aliased,),
        Err(DirectCompactDomainBindingError::Direct(
            DirectRetainedB2nError::InvalidAlias { .. }
        ))
    ));
}

#[test]
fn external_values_and_twiddles_cannot_overlap_any_compact_workspace_range() {
    let external = ArenaSlice::dangling_at_for_test(1, 100, 16);
    let disjoint = ArenaSlice::dangling_at_for_test(2, 200, 16);
    validate_external_workspace_aliases(&[external], &[(disjoint.id(), disjoint)]).unwrap();

    let overlap = ArenaSlice::dangling_at_for_test(3, 108, 16);
    assert_eq!(
        validate_external_workspace_aliases(&[external], &[(overlap.id(), overlap)]),
        Err(DirectCompactDomainBindingError::WorkspaceAlias {
            external: ArenaSlotId(1),
            workspace: ArenaSlotId(3),
        })
    );
    let same_slot_disjoint_address = ArenaSlice::dangling_at_for_test(1, 200, 16);
    assert!(matches!(
        validate_external_workspace_aliases(
            &[external],
            &[(same_slot_disjoint_address.id(), same_slot_disjoint_address)],
        ),
        Err(DirectCompactDomainBindingError::WorkspaceAlias { .. })
    ));
}

fn expected_state_kind(operation: CompactDomainOperation) -> CompactDomainPreparedLaunchKind {
    match operation {
        CompactDomainOperation::LdeBatch { .. } => unreachable!(),
        CompactDomainOperation::AbsorbDomainBatch {
            batch_index,
            first_column,
            columns,
            log_size,
            absorbed_columns_before,
            initializes_state,
            reconstructed_tail,
            ..
        } => CompactDomainPreparedLaunchKind::AbsorbDomainBatch {
            batch_index,
            first_column,
            columns,
            log_size,
            absorbed_columns_before,
            initializes_state,
            tail_columns: reconstructed_tail.map_or(0, |tail| tail.columns),
        },
        CompactDomainOperation::StateExpandInPlace {
            from_log_size,
            to_log_size,
            absorbed_columns,
            bands,
        } => CompactDomainPreparedLaunchKind::StateExpandInPlace {
            from_log_size,
            to_log_size,
            absorbed_columns,
            bands,
        },
        CompactDomainOperation::FinalizeInPlace {
            log_size,
            absorbed_columns,
            reconstructed_tail,
            ..
        } => CompactDomainPreparedLaunchKind::FinalizeInPlace {
            log_size,
            absorbed_columns,
            tail_columns: reconstructed_tail.columns,
        },
    }
}
