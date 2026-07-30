use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};

use super::*;
use crate::backend::progressive_commit::{
    lifted_column_index, ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
    ProgressiveCommitPlan,
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
    let base = base_program(coefficient_logs, lifting_log_size);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let fused = FusedCompactDomainProgram::compile(&base, &domain, &compact).unwrap();
    (base, domain, compact, fused)
}

fn base_program(coefficient_logs: &[u32], lifting_log_size: u32) -> CommitProgram {
    CommitProgram::compile(
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
    .unwrap()
}

#[test]
fn seventeen_expansions_collapse_to_seventeen_disjoint_fused_launches() {
    let logs = (3..=20).collect::<Vec<_>>();
    let (_, domain, compact, fused) = programs(&logs, 21);
    let receipt = fused.receipt();

    assert_eq!(receipt.transitions.len(), 17);
    assert_eq!(receipt.qualified_slab_capacity_words, 50_331_696);
    assert_eq!(receipt.compact_reduced_slab_words, 16_777_264);
    assert_eq!(receipt.peak_transition_words, 25_165_872);
    assert_eq!(receipt.current_expansion_kernel_launches, 204);
    assert_eq!(receipt.current_expand_absorb_kernel_launches, 221);
    assert_eq!(receipt.fused_expand_absorb_kernel_launches, 17);
    assert_eq!(
        receipt.current_expand_absorb_kernel_launches,
        receipt.current_expansion_kernel_launches + 17
    );
    assert_eq!(
        receipt.kernel_launches_removed,
        receipt.current_expansion_kernel_launches
    );
    assert_eq!(receipt.device_copies_removed, 17);
    assert_eq!(receipt.expanded_state_write_bytes_removed, 134_216_704);
    assert_eq!(receipt.expanded_state_reread_bytes_removed, 134_216_704);
    assert_eq!(receipt.expansion_scratch_read_bytes_removed, 1_088);
    assert_eq!(receipt.expansion_scratch_write_bytes_removed, 1_088);
    assert_eq!(receipt.current_leaf_compressions, 3_145_728);
    assert_eq!(receipt.fused_leaf_compressions, 3_145_728);
    assert_eq!(
        receipt.current_leaf_traffic,
        CommitProgramTraffic {
            owned_read_bytes: 482_639_360,
            owned_write_bytes: 398_753_152,
            kernel_launches: 333,
            device_copies: 17,
        }
    );
    assert_eq!(
        receipt.fused_leaf_traffic,
        CommitProgramTraffic {
            owned_read_bytes: 348_421_568,
            owned_write_bytes: 264_535_360,
            kernel_launches: 129,
            device_copies: 0,
        }
    );
    assert_eq!(receipt.qualified_slab_capacity_words, domain.slab_words());
    assert_eq!(receipt.compact_reduced_slab_words, compact.slab_words());
    assert!(receipt.qualified_slab_capacity_words > receipt.compact_reduced_slab_words);
    assert!(receipt.peak_transition_words > receipt.compact_reduced_slab_words);
    assert!(receipt.peak_transition_words <= receipt.qualified_slab_capacity_words);
    assert_eq!(
        receipt.current_leaf_compressions,
        receipt.fused_leaf_compressions
    );
    assert_eq!(
        receipt.current_leaf_traffic.owned_read_bytes - receipt.fused_leaf_traffic.owned_read_bytes,
        receipt.expanded_state_reread_bytes_removed + receipt.expansion_scratch_read_bytes_removed
    );
    assert_eq!(
        receipt.current_leaf_traffic.owned_write_bytes
            - receipt.fused_leaf_traffic.owned_write_bytes,
        receipt.expanded_state_write_bytes_removed + receipt.expansion_scratch_write_bytes_removed
    );
    assert_eq!(
        receipt.current_leaf_traffic.kernel_launches - receipt.fused_leaf_traffic.kernel_launches,
        receipt.kernel_launches_removed
    );
    assert_eq!(
        receipt.current_leaf_traffic.device_copies - receipt.fused_leaf_traffic.device_copies,
        receipt.device_copies_removed
    );

    for transition in &receipt.transitions {
        assert_eq!(
            transition.source_state.len_words,
            compact_state_words(transition.from_log_size).unwrap()
        );
        assert_eq!(
            transition.destination_state.len_words,
            compact_state_words(transition.to_log_size).unwrap()
        );
        assert!(disjoint(transition.source_state, transition.destination_state).unwrap());
        assert!(disjoint(transition.source_state, transition.scratch).unwrap());
        assert!(disjoint(transition.destination_state, transition.scratch).unwrap());
        assert_eq!(
            transition.peak_words,
            transition.source_state.len_words
                + transition.destination_state.len_words
                + transition.scratch.len_words
        );
        assert!(transition.peak_words <= transition.qualified_slab_capacity_words);
        assert_eq!(
            transition.current_traffic.owned_read_bytes - transition.fused_traffic.owned_read_bytes,
            transition.expanded_state_reread_bytes_removed
                + transition.expansion_scratch_read_bytes_removed
        );
        assert_eq!(
            transition.current_traffic.owned_write_bytes
                - transition.fused_traffic.owned_write_bytes,
            transition.expanded_state_write_bytes_removed
                + transition.expansion_scratch_write_bytes_removed
        );
        assert_eq!(
            transition.current_traffic.kernel_launches,
            transition.expansion_bands + 1
        );
        assert_eq!(transition.fused_traffic.kernel_launches, 1);
    }
}

#[test]
fn fused_oracle_matches_canonical_progressive_bytes_and_mutations() {
    let logs = [vec![3; 17], vec![4; 16], vec![5; 1]].concat();
    let (base, domain, compact, fused) = programs(&logs, 6);
    let fixture = base.fixture(0x5eed_f00d).unwrap();
    let independent = fused_leaf_oracle(
        &fused,
        &base.requirements().leaves.plan,
        &fixture.evaluations,
    );
    assert_eq!(independent, fixture.oracle.leaf_hashes);
    assert_eq!(
        fused
            .oracle(&base, &domain, &compact, &fixture.evaluations)
            .unwrap()
            .leaf_hashes,
        independent
    );

    let mut mutated = fixture.evaluations.clone();
    let column = mutated.len() - 1;
    let row = mutated[column].len() - 1;
    mutated[column][row] ^= 0x005a_5a5a;
    let changed = fused_leaf_oracle(&fused, &base.requirements().leaves.plan, &mutated);
    assert_ne!(changed, independent);
    assert_eq!(
        changed,
        fused
            .oracle(&base, &domain, &compact, &mutated)
            .unwrap()
            .leaf_hashes
    );
}

#[test]
fn ping_pong_parity_ends_at_merkle_base_without_hidden_copy() {
    let cases = [
        (vec![5; 17], 6, 0usize),
        ([vec![5; 17], vec![6; 16]].concat(), 7, 1),
        ([vec![5; 17], vec![6; 16], vec![7; 1]].concat(), 8, 2),
    ];

    for (case, (logs, lifting_log_size, expected_transitions)) in cases.into_iter().enumerate() {
        let (base, domain, compact, fused) = programs(&logs, lifting_log_size);
        assert_eq!(fused.receipt().transitions.len(), expected_transitions);
        assert_eq!(fused.receipt().fused_leaf_traffic.device_copies, 0);
        assert!(fused
            .receipt()
            .transitions
            .iter()
            .all(|transition| transition.fused_traffic.device_copies == 0));

        let initial = fused
            .steps()
            .iter()
            .find_map(|step| match step.operation {
                FusedCompactDomainOperation::AbsorbDomainBatch {
                    initializes_state: true,
                    state,
                    ..
                } => Some(state),
                _ => None,
            })
            .unwrap();
        let final_state = fused
            .steps()
            .iter()
            .find_map(|step| match step.operation {
                FusedCompactDomainOperation::FinalizeInPlace { state, .. } => Some(state),
                _ => None,
            })
            .unwrap();
        let state_capacity =
            fused.receipt().qualified_slab_capacity_words - PROGRESSIVE_IN_PLACE_SCRATCH_WORDS;
        let expected_initial_offset = if expected_transitions % 2 == 1 {
            state_capacity - initial.len_words
        } else {
            0
        };
        assert_eq!(initial.offset_words, expected_initial_offset);
        assert_eq!(final_state.offset_words, 0);
        assert_eq!(
            final_state.len_words,
            compact_state_words(lifting_log_size).unwrap()
        );

        let fixture = base.fixture(0x51ab_0000 + case as u64).unwrap();
        let expected = fused_leaf_oracle(
            &fused,
            &base.requirements().leaves.plan,
            &fixture.evaluations,
        );
        assert_eq!(expected, fixture.oracle.leaf_hashes);
        let mut mutated = fixture.evaluations.clone();
        let last_column = mutated.last_mut().unwrap();
        *last_column.last_mut().unwrap() ^= 0x00c0_ffee;
        let changed = fused_leaf_oracle(&fused, &base.requirements().leaves.plan, &mutated);
        assert_ne!(changed, expected);
        assert_eq!(
            changed,
            fused
                .oracle(&base, &domain, &compact, &mutated)
                .unwrap()
                .leaf_hashes
        );
    }
}

#[test]
fn final_expansion_without_absorb_fails_closed() {
    let base = base_program(&[3; 17], 6);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    assert!(matches!(
        FusedCompactDomainProgram::compile(&base, &domain, &compact),
        Err(FusedCompactDomainProgramError::ExpansionNotFollowedByAbsorb { .. })
    ));
}

#[test]
fn nonadjacent_absorb_and_reduced_slab_capacity_fail_closed() {
    let base = base_program(&[3, 4, 5], 6);
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let mut steps = compact.steps().to_vec();
    let expansion = steps
        .iter()
        .position(|step| {
            matches!(
                step.operation,
                CompactDomainOperation::StateExpandInPlace { .. }
            )
        })
        .unwrap();
    steps.swap(expansion + 1, expansion + 2);
    assert_eq!(
        compile_steps(
            compact.cache_key(),
            &steps,
            compact.merkle_suffix(),
            compact.comparison(),
            domain.slab_words(),
            compact.slab_words(),
        ),
        Err(FusedCompactDomainProgramError::ExpansionNotFollowedByAbsorb { step: expansion })
    );

    let mut reduced = compact.comparison();
    reduced.current_state_slab_words = compact.slab_words();
    assert!(matches!(
        compile_steps(
            compact.cache_key(),
            compact.steps(),
            compact.merkle_suffix(),
            reduced,
            compact.slab_words(),
            compact.slab_words(),
        ),
        Err(FusedCompactDomainProgramError::SlabCapacity { .. })
    ));
}

#[test]
fn batch_tail_compression_and_program_mutations_are_rejected() {
    let (base, domain, compact, mut fused) = programs(&[3, 4, 5], 6);
    let mut steps = compact.steps().to_vec();
    let absorb = steps
        .iter_mut()
        .find(|step| {
            matches!(
                step.operation,
                CompactDomainOperation::AbsorbDomainBatch {
                    initializes_state: false,
                    ..
                }
            )
        })
        .unwrap();
    let CompactDomainOperation::AbsorbDomainBatch {
        batch_index,
        first_column,
        columns,
        log_size,
        absorbed_columns_before,
        initializes_state,
        leaf_compressions,
        ..
    } = absorb.operation
    else {
        unreachable!()
    };
    absorb.operation = CompactDomainOperation::AbsorbDomainBatch {
        batch_index,
        first_column,
        columns,
        log_size,
        absorbed_columns_before,
        initializes_state,
        reconstructed_tail: Some(CompactDomainTail {
            first_column: 0,
            columns: 16,
        }),
        leaf_compressions,
    };
    assert_eq!(
        compile_steps(
            compact.cache_key(),
            &steps,
            compact.merkle_suffix(),
            compact.comparison(),
            domain.slab_words(),
            compact.slab_words(),
        ),
        Err(FusedCompactDomainProgramError::NonCanonicalBatch)
    );

    fused.steps[0].traffic.owned_read_bytes += 4;
    assert_eq!(
        fused.validate_against(&base, &domain, &compact),
        Err(FusedCompactDomainProgramError::NonCanonicalProgram)
    );
}

#[derive(Clone, Default)]
struct AbstractH8State {
    compressed_prefix: Vec<u32>,
}

fn fused_leaf_oracle(
    program: &FusedCompactDomainProgram,
    plan: &ProgressiveCommitPlan,
    evaluations: &[Vec<u32>],
) -> Vec<Blake2sHash> {
    let mut states: Option<Vec<AbstractH8State>> = None;
    for step in program.steps() {
        match step.operation {
            FusedCompactDomainOperation::LdeBatch { .. } => {}
            FusedCompactDomainOperation::AbsorbDomainBatch {
                first_column,
                columns,
                log_size,
                absorbed_columns_before,
                initializes_state,
                ..
            } => {
                if initializes_state {
                    assert!(states.is_none());
                    states = Some(vec![AbstractH8State::default(); 1usize << log_size]);
                }
                absorb(
                    states.as_mut().unwrap(),
                    plan,
                    evaluations,
                    first_column,
                    columns,
                    log_size,
                    absorbed_columns_before,
                );
            }
            FusedCompactDomainOperation::ExpandAbsorbDomainBatch {
                first_column,
                columns,
                from_log_size,
                to_log_size,
                absorbed_columns_before,
                ..
            } => {
                let source = states.take().unwrap();
                let mut destination = (0..1usize << to_log_size)
                    .map(|row| source[lifted_column_index(row, from_log_size, to_log_size)].clone())
                    .collect::<Vec<_>>();
                absorb(
                    &mut destination,
                    plan,
                    evaluations,
                    first_column,
                    columns,
                    to_log_size,
                    absorbed_columns_before,
                );
                states = Some(destination);
            }
            FusedCompactDomainOperation::FinalizeInPlace {
                log_size,
                absorbed_columns,
                ..
            } => {
                let pending = pending_words(absorbed_columns as usize);
                return states
                    .take()
                    .unwrap()
                    .into_iter()
                    .enumerate()
                    .map(|(row, mut state)| {
                        for column in absorbed_columns as usize - pending..absorbed_columns as usize
                        {
                            state.compressed_prefix.push(value_at(
                                evaluations,
                                plan,
                                column,
                                row,
                                log_size,
                            ));
                        }
                        assert_eq!(state.compressed_prefix.len(), absorbed_columns as usize);
                        let mut hasher = Blake2sHasherGeneric::<false>::default();
                        for word in state.compressed_prefix {
                            hasher.update(&word.to_le_bytes());
                        }
                        hasher.finalize()
                    })
                    .collect();
            }
        }
    }
    panic!("missing finalize")
}

#[allow(clippy::too_many_arguments)]
fn absorb(
    states: &mut [AbstractH8State],
    plan: &ProgressiveCommitPlan,
    evaluations: &[Vec<u32>],
    first_column: u32,
    columns: u32,
    log_size: u32,
    absorbed_columns: u32,
) {
    let pending = pending_words(absorbed_columns as usize);
    for (row, state) in states.iter_mut().enumerate() {
        let mut stream = core::mem::take(&mut state.compressed_prefix);
        for column in absorbed_columns as usize - pending..absorbed_columns as usize {
            stream.push(value_at(evaluations, plan, column, row, log_size));
        }
        for column in first_column as usize..(first_column + columns) as usize {
            stream.push(value_at(evaluations, plan, column, row, log_size));
        }
        let total = (absorbed_columns + columns) as usize;
        stream.truncate(total - pending_words(total));
        assert_eq!(stream.len() % 16, 0);
        state.compressed_prefix = stream;
    }
}

fn value_at(
    evaluations: &[Vec<u32>],
    plan: &ProgressiveCommitPlan,
    column: usize,
    row: usize,
    target_log: u32,
) -> u32 {
    let source_log = plan.columns[column].evaluation_log_size;
    evaluations[column][lifted_column_index(row, source_log, target_log)]
}

fn pending_words(columns: usize) -> usize {
    if columns == 0 {
        0
    } else {
        (columns - 1) % 16 + 1
    }
}
