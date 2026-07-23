use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn base_program() -> CommitProgram {
    CommitProgram::compile(
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
    .unwrap()
}

fn programs() -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
) {
    let base = base_program();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    (base, domain, compact)
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

fn prepared_batches(
    requirements: &ProgressiveLeafWorkspaceRequirements,
) -> Vec<(PreparedBatch, Vec<ProgressiveLdeSegment>)> {
    let mut absorbed = 0u32;
    requirements
        .plan
        .lde_batches
        .iter()
        .enumerate()
        .map(|(batch_index, batch)| {
            let columns = batch.columns.len();
            let prepared = PreparedBatch {
                coefficient_ptrs: ArenaSlice::dangling_for_test(
                    200 + 3 * batch_index as u32,
                    columns * POINTER_WORDS,
                ),
                coefficient_sizes: ArenaSlice::dangling_for_test(
                    201 + 3 * batch_index as u32,
                    columns,
                ),
                output_ptrs: ArenaSlice::dangling_for_test(
                    202 + 3 * batch_index as u32,
                    columns * POINTER_WORDS,
                ),
                batch_index: batch_index as u32,
                segment_offset: 0,
                log_size: batch.evaluation_log_size,
                columns: columns as u32,
                absorbed_columns_before: absorbed,
            };
            absorbed += columns as u32;
            (
                prepared,
                vec![ProgressiveLdeSegment {
                    offset: 0,
                    columns,
                    kind: ProgressiveLdeSegmentKind::Separate,
                }],
            )
        })
        .collect()
}

fn expected_kind(operation: CompactDomainOperation) -> CompactDomainPreparedLaunchKind {
    match operation {
        CompactDomainOperation::LdeBatch {
            batch_index,
            first_column,
            columns,
            log_size,
        } => CompactDomainPreparedLaunchKind::LdeBatch {
            batch_index,
            first_column,
            columns,
            log_size,
        },
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

#[test]
fn tail_abi_is_fixed_and_capture_parameters_outlive_mutated_dropped_builder() {
    assert_eq!(core::mem::size_of::<CompactBlake2sTailDescriptor>(), 192);
    assert_eq!(core::mem::align_of::<CompactBlake2sTailDescriptor>(), 8);
    assert_eq!(
        core::mem::offset_of!(CompactBlake2sTailDescriptor, column_addresses),
        0
    );
    assert_eq!(
        core::mem::offset_of!(CompactBlake2sTailDescriptor, log_ratios),
        128
    );

    let mut host_builder = vec![(0x1000_u64, 3_u32), (0x2000, 5), (0x3000, 7)];
    let captured_parameter = descriptor_from_sources(&host_builder).unwrap();
    let expected = captured_parameter;
    host_builder.fill((0xdead_beef, 30));
    drop(host_builder);

    assert_eq!(captured_parameter, expected);
    assert_eq!(
        &captured_parameter.column_addresses[..3],
        &[0x1000, 0x2000, 0x3000]
    );
    assert_eq!(&captured_parameter.log_ratios[..3], &[3, 5, 7]);
    assert!(captured_parameter.column_addresses[3..]
        .iter()
        .all(|&ptr| ptr == 0));
    assert!(captured_parameter.log_ratios[3..]
        .iter()
        .all(|&log| log == 0));
}

#[test]
fn compact_admission_derives_legacy_shape_then_narrows_only_the_shared_slab() {
    let (base, domain, compact) = programs();
    let slots = slots(base.requirements());
    let legacy = base
        .requirements()
        .arena_slot_requirements_in_place(&slots)
        .unwrap();
    let narrowed =
        compact_domain_arena_slot_requirements(&compact, &base, &domain, &slots).unwrap();
    let legacy_slab = legacy
        .iter()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .unwrap();
    let compact_slab = narrowed
        .iter()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .unwrap();
    assert_eq!(legacy_slab.len_words, domain.slab_words());
    assert_eq!(compact_slab.len_words, compact.slab_words());
    assert_eq!(
        compact_slab.len_words,
        base.requirements().merkle.leaf_words + PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
    );
    assert_eq!(legacy_slab.alignment_words, STATE_ALIGNMENT_WORDS);
    assert_eq!(compact_slab.alignment_words, HASH_WORDS);
    assert_eq!(
        legacy_slab.len_words - compact_slab.len_words,
        2 * (1 << 7) * HASH_WORDS
    );

    let mut split_merkle_scratch = slots;
    split_merkle_scratch.merkle.merkle_scratch = Some(ArenaSlotId(999));
    assert!(compact_domain_arena_slot_requirements(
        &compact,
        &base,
        &domain,
        &split_merkle_scratch
    )
    .is_err());
}

#[test]
fn exact_compact_operations_bind_batches_tails_state_and_shared_scratch() {
    let (base, _domain, compact) = programs();
    let requirements = base.requirements();
    let retained = retained_outputs(&requirements.leaves.plan);
    let slab = ArenaSlice::dangling_at_for_test(1, 50_000, compact.slab_words());
    let scratch = slab
        .checked_subslice(
            compact.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    let launches = bind_compact_launches(
        &compact,
        requirements,
        prepared_batches(&requirements.leaves),
        &retained,
        slab,
        scratch,
    )
    .unwrap();
    let actual = launches
        .iter()
        .copied()
        .map(CompactPreparedLaunch::kind)
        .collect::<Vec<_>>();
    let expected = compact
        .steps()
        .iter()
        .map(|step| expected_kind(step.operation))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);

    for launch in launches {
        match launch {
            CompactPreparedLaunch::State(CompactStatePreparedLaunch::Absorb {
                tail_columns,
                tail,
                states,
                ..
            })
            | CompactPreparedLaunch::State(CompactStatePreparedLaunch::FinalizeInPlace {
                tail_columns,
                tail,
                states_and_hashes: states,
                ..
            }) => {
                assert_eq!(states.as_u32_ptr(), slab.as_u32_ptr());
                for index in 0..tail_columns as usize {
                    let canonical = retained
                        .iter()
                        .position(|output| {
                            output.is_some_and(|output| {
                                output.as_u32_ptr() as u64 == tail.column_addresses[index]
                            })
                        })
                        .unwrap();
                    let target_log = match launch.kind() {
                        CompactDomainPreparedLaunchKind::AbsorbDomainBatch { log_size, .. }
                        | CompactDomainPreparedLaunchKind::FinalizeInPlace { log_size, .. } => {
                            log_size
                        }
                        _ => unreachable!(),
                    };
                    assert_eq!(
                        tail.log_ratios[index],
                        target_log
                            - requirements.leaves.plan.columns[canonical].evaluation_log_size
                    );
                }
                assert!(tail.column_addresses[tail_columns as usize..]
                    .iter()
                    .all(|&ptr| ptr == 0));
            }
            CompactPreparedLaunch::State(CompactStatePreparedLaunch::ExpandInPlace {
                states,
                scratch_pair,
                ..
            }) => {
                assert_eq!(states.as_u32_ptr(), slab.as_u32_ptr());
                assert_eq!(scratch_pair.as_u32_ptr(), scratch.as_u32_ptr());
                assert_eq!(scratch_pair.len_words(), PROGRESSIVE_IN_PLACE_SCRATCH_WORDS);
            }
            CompactPreparedLaunch::Lde(_) => {}
        }
    }
}

#[test]
fn missing_retained_tail_and_noncanonical_batch_fail_before_native_dispatch() {
    let (base, _domain, compact) = programs();
    let requirements = base.requirements();
    let mut retained = retained_outputs(&requirements.leaves.plan);
    retained[16] = None;
    let slab = ArenaSlice::dangling_at_for_test(1, 50_000, compact.slab_words());
    let scratch = slab
        .checked_subslice(
            compact.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    assert!(matches!(
        bind_compact_launches(
            &compact,
            requirements,
            prepared_batches(&requirements.leaves),
            &retained,
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::MissingTailOutput(16))
    ));

    let mut invalid_batches = prepared_batches(&requirements.leaves);
    invalid_batches[0].1[0].kind = ProgressiveLdeSegmentKind::Fused16 {
        retained_write_mask: 0xffff,
    };
    assert!(matches!(
        bind_compact_launches(
            &compact,
            requirements,
            invalid_batches,
            &retained_outputs(&requirements.leaves.plan),
            slab,
            scratch,
        ),
        Err(CompactDomainBindingError::InvalidBatch(0))
    ));
}

#[test]
fn compact_admission_rejects_program_identity_drift() {
    let (base, domain, compact) = programs();
    let drifted = CommitProgram::compile(
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
        compact_domain_arena_slot_requirements(
            &compact,
            &drifted,
            &domain,
            &slots(drifted.requirements()),
        ),
        Err(CompactDomainBindingError::Program(_))
    ));
}
