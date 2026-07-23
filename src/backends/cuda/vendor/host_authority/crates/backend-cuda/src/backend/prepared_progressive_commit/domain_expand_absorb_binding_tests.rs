use super::*;
use crate::backend::prepared_decommit::TraceTreeRole;
use crate::backend::progressive_commit::{
    lifted_column_index, ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn programs(
    coefficient_logs: &[u32],
    lifting_log_size: u32,
) -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
    FusedCompactDomainProgram,
) {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: coefficient_logs.to_vec(),
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let fused = FusedCompactDomainProgram::compile(&base, &domain, &compact).unwrap();
    (base, domain, compact, fused)
}

fn retained_outputs(plan: &ProgressiveCommitPlan) -> Vec<Option<ArenaSlice>> {
    plan.columns
        .iter()
        .enumerate()
        .map(|(canonical, column)| {
            Some(ArenaSlice::dangling_at_for_test(
                1_000 + canonical as u32,
                20_000 + canonical * (1 << 12),
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

fn workspace_slots(
    requirements: &ProgressiveCommitWorkspaceRequirements,
) -> ProgressiveCommitWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    let slab = id();
    ProgressiveCommitWorkspaceSlots {
        leaves: ProgressiveLeafWorkspaceSlots {
            lde_scratch: requirements.leaves.lde_scratch_words.map(|_| id()),
            state_ping: slab,
            state_pong: requirements.leaves.state_pong_words.map(|_| slab),
            leaf_hashes: slab,
            batches: requirements
                .leaves
                .batches
                .iter()
                .map(|_| ProgressiveBatchSlots {
                    coefficient_ptrs: id(),
                    coefficient_sizes: id(),
                    output_ptrs: id(),
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
                .map(|_| id())
                .collect(),
            tail_level_ptrs: requirements.merkle.tail_pointer_words.map(|_| id()),
            tail_outputs: requirements
                .merkle
                .tail_outputs
                .iter()
                .map(|_| id())
                .collect(),
        },
    }
}

fn bound_launches(
    base: &CommitProgram,
    domain: &DomainCooperativeProgram,
    fused: &FusedCompactDomainProgram,
) -> (
    ArenaSlice,
    ArenaSlice,
    Vec<Option<ArenaSlice>>,
    Vec<PreparedLaunch>,
) {
    let slab = ArenaSlice::dangling_at_for_test(1, 30_000, domain.slab_words());
    let scratch = slab
        .checked_subslice(
            domain.slab_words() - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
            PROGRESSIVE_IN_PLACE_SCRATCH_WORDS,
        )
        .unwrap();
    let retained = retained_outputs(&base.requirements().leaves.plan);
    let launches = bind_launches(
        fused,
        base.requirements(),
        prepared_batches(&base.requirements().leaves),
        &retained,
        slab,
        scratch,
    )
    .unwrap();
    (slab, scratch, retained, launches)
}

fn target_row(source: u32, child: u32, delta: u32) -> u32 {
    let expansion = 1u32 << delta;
    2 * (expansion * (source >> 1) + child) + (source & 1)
}

#[test]
fn source_major_mapping_is_exhaustive_unique_and_inverse_to_circle_lifting() {
    for from_log in 1..=7 {
        for to_log in from_log + 1..=9 {
            let delta = to_log - from_log;
            let expansion = 1u32 << delta;
            let mut seen = vec![false; 1usize << to_log];
            for source in 0..1u32 << from_log {
                for child in 0..expansion {
                    let target = target_row(source, child, delta);
                    assert_eq!(
                        lifted_column_index(target as usize, from_log, to_log),
                        source as usize
                    );
                    assert!(!core::mem::replace(&mut seen[target as usize], true));
                }
            }
            assert!(seen.into_iter().all(core::convert::identity));
        }
    }
    let source = include_str!("../../../../backend-cuda-kernels/cuda/blake2s_quad.cu");
    assert!(source.contains("2u * (expansion * source_pair + child) + parity"));
}

#[test]
fn one_source_image_fans_out_once_and_mutation_changes_exactly_its_children() {
    for delta in 1..=5 {
        let from_log = 4;
        let expansion = 1usize << delta;
        let source = (0..1usize << from_log).collect::<Vec<_>>();
        let expand = |values: &[usize]| {
            let mut output = vec![usize::MAX; values.len() * expansion];
            for (row, &value) in values.iter().enumerate() {
                for child in 0..expansion {
                    output[target_row(row as u32, child as u32, delta) as usize] = value;
                }
            }
            output
        };
        let baseline = expand(&source);
        let mut mutated = source.clone();
        mutated[7] = usize::MAX - 7;
        let candidate = expand(&mutated);
        let changed = baseline
            .iter()
            .zip(&candidate)
            .filter(|(left, right)| left != right)
            .count();
        assert_eq!(changed, expansion);
        assert_eq!(
            baseline.iter().filter(|&&value| value == 7).count(),
            expansion
        );
    }
}

#[test]
fn exact_nonzero_spans_bind_and_partial_overlap_alignment_and_overflow_fail() {
    let slab = ArenaSlice::dangling_at_for_test(1, 10_000, 512);
    let source = bind_state(
        slab,
        DomainCooperativeSlabSlice {
            offset_words: 256,
            len_words: 32,
        },
        2,
    )
    .unwrap();
    let destination = bind_state(
        slab,
        DomainCooperativeSlabSlice {
            offset_words: 0,
            len_words: 64,
        },
        3,
    )
    .unwrap();
    let scratch = slab.checked_subslice(464, 48).unwrap();
    validate_transition(source, destination, scratch, scratch).unwrap();

    let partial = slab.checked_subslice(272, 64).unwrap();
    assert_eq!(
        validate_transition(source, partial, scratch, scratch),
        Err(FusedCompactDomainBindingError::SpanOverlap)
    );
    assert!(matches!(
        bind_state(
            slab,
            DomainCooperativeSlabSlice {
                offset_words: 257,
                len_words: 32,
            },
            2,
        ),
        Err(FusedCompactDomainBindingError::StateSpan)
    ));
    assert!(matches!(
        bind_state(
            slab,
            DomainCooperativeSlabSlice {
                offset_words: 0,
                len_words: 8,
            },
            usize::BITS,
        ),
        Err(FusedCompactDomainBindingError::UnsupportedLogSize(_))
    ));
    assert_eq!(
        slice_range(ArenaSlice::dangling_for_test(9, usize::MAX)),
        Err(FusedCompactDomainBindingError::SizeOverflow)
    );
    let wrong_scratch = slab.checked_subslice(456, 48).unwrap();
    assert_eq!(
        validate_transition(source, destination, wrong_scratch, scratch),
        Err(FusedCompactDomainBindingError::ScratchPair)
    );
}

#[test]
fn arbitrary_log_jump_binds_target_tail_ratios_and_exact_program_spans() {
    let logs = [vec![3; 17], vec![7; 16]].concat();
    let (base, domain, _compact, fused) = programs(&logs, 8);
    let (slab, scratch, retained, launches) = bound_launches(&base, &domain, &fused);
    assert_eq!(
        launches
            .iter()
            .map(|launch| launch.operation)
            .collect::<Vec<_>>(),
        fused
            .steps()
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>()
    );
    let transition = launches
        .iter()
        .find_map(|launch| match (launch.operation, launch.bound) {
            (
                FusedCompactDomainOperation::ExpandAbsorbDomainBatch {
                    from_log_size,
                    to_log_size,
                    source_state,
                    destination_state,
                    scratch: model_scratch,
                    ..
                },
                BoundLaunch::ExpandAbsorb {
                    tail_columns,
                    tail,
                    source_state: source,
                    destination_state: destination,
                    ..
                },
            ) => Some((
                from_log_size,
                to_log_size,
                source_state,
                destination_state,
                model_scratch,
                tail_columns,
                tail,
                source,
                destination,
            )),
            _ => None,
        })
        .unwrap();
    assert_eq!((transition.0, transition.1), (4, 8));
    assert_eq!(transition.5, 1);
    assert_eq!(
        transition.6.column_addresses[0],
        retained[16].unwrap().as_u32_ptr() as u64
    );
    assert_eq!(transition.6.log_ratios[0], 4);
    assert_eq!(
        transition.7.as_u32_ptr(),
        slab.as_u32_ptr().wrapping_add(transition.2.offset_words)
    );
    assert_eq!(
        transition.8.as_u32_ptr(),
        slab.as_u32_ptr().wrapping_add(transition.3.offset_words)
    );
    assert_eq!(transition.4.offset_words, domain.slab_words() - 48);
    assert_eq!(
        scratch.as_u32_ptr(),
        slab.as_u32_ptr().wrapping_add(transition.4.offset_words)
    );
    assert_eq!(
        fused.receipt().transitions[0].fused_traffic.kernel_launches,
        1
    );
}

#[test]
fn odd_even_and_zero_transition_bindings_finalize_at_slab_base() {
    let cases = [
        (vec![5; 17], 6, 0usize),
        ([vec![5; 17], vec![6; 16]].concat(), 7, 1),
        ([vec![5; 17], vec![6; 16], vec![7; 1]].concat(), 8, 2),
    ];
    for (logs, lifting_log_size, transition_count) in cases {
        let (base, domain, _compact, fused) = programs(&logs, lifting_log_size);
        let (slab, _, _, launches) = bound_launches(&base, &domain, &fused);
        assert_eq!(fused.receipt().transitions.len(), transition_count);
        let initial = launches
            .iter()
            .find_map(|launch| match launch.bound {
                BoundLaunch::Compact(CompactStatePreparedLaunch::Absorb {
                    initializes_state: true,
                    states,
                    ..
                }) => Some(states),
                _ => None,
            })
            .unwrap();
        let final_state = launches
            .iter()
            .find_map(|launch| match launch.bound {
                BoundLaunch::Compact(CompactStatePreparedLaunch::FinalizeInPlace {
                    states_and_hashes,
                    ..
                }) => Some(states_and_hashes),
                _ => None,
            })
            .unwrap();
        assert_eq!(final_state.as_u32_ptr(), slab.as_u32_ptr());
        assert_eq!(
            initial.as_u32_ptr() == slab.as_u32_ptr(),
            transition_count % 2 == 0
        );
    }
}

#[test]
fn same_log_successor_batch_stays_an_ordinary_noninitializing_absorb() {
    let logs = vec![3; 65_536];
    let (base, domain, _compact, fused) = programs(&logs, 4);
    assert!(fused.receipt().transitions.is_empty());
    let (_, _, _, launches) = bound_launches(&base, &domain, &fused);
    let absorbs = launches
        .iter()
        .filter_map(|launch| match launch.bound {
            BoundLaunch::Compact(CompactStatePreparedLaunch::Absorb {
                initializes_state,
                tail_columns,
                states,
                ..
            }) => Some((initializes_state, tail_columns, states)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(absorbs.len(), 2);
    assert_eq!((absorbs[0].0, absorbs[0].1), (true, 0));
    assert_eq!((absorbs[1].0, absorbs[1].1), (false, 15));
    assert_eq!(absorbs[0].2.as_u32_ptr(), absorbs[1].2.as_u32_ptr());
}

#[test]
fn architecture_and_qualified_slab_admission_fail_closed() {
    assert!(!fused_compact_domain_arch_supported(7, 5));
    assert!(fused_compact_domain_arch_supported(8, 0));
    assert!(fused_compact_domain_arch_supported(9, 0));

    let (base, domain, compact, fused) = programs(&[5; 17], 6);
    let slots = workspace_slots(base.requirements());
    let workspace =
        fused_compact_domain_arena_slot_requirements(&fused, &base, &domain, &compact, &slots)
            .unwrap();
    let slab = workspace
        .iter()
        .find(|requirement| requirement.id == slots.leaves.state_ping)
        .unwrap();
    assert_eq!(slab.len_words, domain.slab_words());
    assert!(slab.len_words > compact.slab_words());
}

#[test]
fn materialized_binder_cannot_replace_a_qualified_terminal_batch() {
    let (base, _domain, compact, _fused) = programs(&[12; 16], 13);
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    let terminal = DirectCompactTerminalProgram::compile(&compact, &direct).unwrap();
    assert!(matches!(
        terminal.receipt().batches[0].mode,
        DirectCompactTerminalBatchMode::Fixed16Hybrid { .. }
    ));
    assert_eq!(
        fused_compact_domain_materialized_only_admission(&terminal),
        Err(FusedCompactDomainBindingError::QualifiedTerminalConflict { batch_index: 0 })
    );

    let (base, _domain, compact, _fused) = programs(&[5; 17], 6);
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    let terminal = DirectCompactTerminalProgram::compile(&compact, &direct).unwrap();
    assert!(terminal
        .receipt()
        .batches
        .iter()
        .all(|batch| matches!(batch.mode, DirectCompactTerminalBatchMode::Materialized)));
    fused_compact_domain_materialized_only_admission(&terminal).unwrap();
}
