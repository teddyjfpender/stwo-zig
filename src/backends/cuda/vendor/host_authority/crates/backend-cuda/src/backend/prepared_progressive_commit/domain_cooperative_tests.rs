use super::*;
use crate::backend::progressive_commit::{
    full_lifting_leaf_oracle, merkle_root, progressive_leaf_oracle, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry,
};

fn base_program(logs: &[u32], lifting: u32) -> CommitProgram {
    CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: lifting,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: lifting,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: logs.to_vec(),
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap()
}

fn absorb_operations(program: &DomainCooperativeProgram) -> Vec<DomainCooperativeOperation> {
    program
        .steps()
        .iter()
        .filter_map(|step| {
            matches!(
                step.operation,
                DomainCooperativeOperation::AbsorbDomainBatch { .. }
            )
            .then_some(step.operation)
        })
        .collect()
}

#[test]
fn pending_and_compression_boundaries_are_exact() {
    for columns in [1usize, 15, 16, 17, 31, 32, 33, 65] {
        let base = base_program(&vec![3; columns], 6);
        let program = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
        let operations = absorb_operations(&program);
        assert_eq!(operations.len(), 1);
        let DomainCooperativeOperation::AbsorbDomainBatch {
            first_column,
            columns: actual_columns,
            log_size,
            absorbed_columns_before,
            pending_before_words,
            pending_after_words,
            initializes_state,
            state,
            leaf_compressions,
            ..
        } = operations[0]
        else {
            unreachable!()
        };
        assert_eq!(first_column, 0);
        assert_eq!(actual_columns as usize, columns);
        assert_eq!(log_size, 4);
        assert_eq!(absorbed_columns_before, 0);
        assert_eq!(pending_before_words, 0);
        assert_eq!(pending_after_words as usize, pending_words(columns));
        assert!(initializes_state);
        assert_eq!(state.offset_words, 0);
        assert_eq!(state.len_words, (1usize << 4) * STATE_WORDS);
        assert_eq!(leaf_compressions, ((columns - 1) / 16 * (1 << 4)) as u64);
        assert_eq!(
            program.comparison().replacement_leaf_compressions,
            leaf_compressions + (1 << 6)
        );
        assert_eq!(
            program.comparison().retained_evaluation_reread_bytes,
            (columns * (1 << 4) * core::mem::size_of::<u32>()) as u64
        );
    }
}

#[test]
fn mixed_native_logs_keep_lazy_prefix_and_canonical_compressions() {
    let logs = [vec![3; 17], vec![4; 16], vec![5; 1]].concat();
    let base = base_program(&logs, 6);
    let program = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let operations = absorb_operations(&program);
    assert_eq!(operations.len(), 3);
    let expected = [
        (0, 17, 4, 0, 1, 16u64),
        (17, 16, 5, 1, 1, 32u64),
        (33, 1, 6, 1, 2, 0u64),
    ];
    for (operation, (first, columns, log, before, after, compressions)) in
        operations.iter().zip(expected)
    {
        let DomainCooperativeOperation::AbsorbDomainBatch {
            first_column,
            columns: actual_columns,
            log_size,
            pending_before_words,
            pending_after_words,
            leaf_compressions,
            ..
        } = operation
        else {
            unreachable!()
        };
        assert_eq!(
            (*first_column, *actual_columns, *log_size),
            (first, columns, log)
        );
        assert_eq!(
            (*pending_before_words, *pending_after_words),
            (before, after)
        );
        assert_eq!(*leaf_compressions, compressions);
    }
    let comparison = program.comparison();
    assert_eq!(comparison.replacement_leaf_compressions, 16 + 32 + 64);
    assert_eq!(
        comparison.replacement_leaf_compressions,
        comparison.current_leaf_compressions
    );
    assert!(comparison.replacement_state_api_calls < comparison.current_state_api_calls);
}

#[test]
fn log_rises_cover_one_fifteen_sixteen_and_seventeen_word_prefixes() {
    for prefix in [1usize, 15, 16, 17] {
        let mut logs = vec![3; prefix];
        logs.push(4);
        let program = DomainCooperativeProgram::compile_mode_a(&base_program(&logs, 6)).unwrap();
        let operations = absorb_operations(&program);
        assert_eq!(operations.len(), 2);
        let DomainCooperativeOperation::AbsorbDomainBatch {
            first_column,
            columns,
            pending_before_words,
            pending_after_words,
            leaf_compressions,
            ..
        } = operations[1]
        else {
            unreachable!()
        };
        assert_eq!((first_column as usize, columns), (prefix, 1));
        assert_eq!(pending_before_words as usize, pending_words(prefix));
        assert_eq!(pending_after_words as usize, pending_words(prefix + 1));
        assert_eq!(leaf_compressions, if prefix == 16 { 1 << 5 } else { 0 });
    }
}

#[test]
fn mode_a_charges_readback_and_preserves_the_qualified_suffix() {
    let base = base_program(&vec![12; 65], 14);
    let program = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let comparison = program.comparison();
    assert_eq!(
        comparison.retained_evaluation_reread_bytes,
        65 * (1 << 13) * 4
    );
    assert_eq!(
        comparison.current_retained_evaluation_reread_bytes,
        (1 << 13) * 4
    );
    assert_eq!(
        comparison.incremental_retained_evaluation_reread_bytes,
        64 * (1 << 13) * 4
    );
    assert!(
        comparison.replacement_leaf_traffic.owned_read_bytes
            >= comparison.retained_evaluation_reread_bytes
    );
    let expected_suffix = base
        .steps()
        .iter()
        .copied()
        .skip_while(|step| {
            !matches!(
                step.operation,
                CommitProgramOperation::FinalizeInPlace { .. }
            )
        })
        .skip(1)
        .collect::<Vec<_>>();
    assert_eq!(program.merkle_suffix(), expected_suffix);
    assert_eq!(program.slab_words(), base.in_place_slab_words().unwrap());
    assert_eq!(
        program.resource_model(),
        DomainCooperativeResourceModel {
            threads_per_row: 4,
            rows_per_block: 64,
            threads_per_block: 256,
            launch_bounds_min_blocks_per_sm: 5,
            persistent_state_words_per_thread: 6,
            register_ceiling_per_thread: 48,
        }
    );
    let resource = program.resource_model();
    let launch_bound_registers =
        65_536 / (resource.threads_per_block * resource.launch_bounds_min_blocks_per_sm);
    assert_eq!(launch_bound_registers, 51);
    assert!(
        resource.register_ceiling_per_thread <= launch_bound_registers,
        "the explicit 48-register policy must satisfy the five-block native launch bound"
    );
}

#[test]
fn retained_same_log_batch_crosses_group_edges_without_reordering() {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 6,
            log_blowup_factor: 1,
            groups: vec![
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 3],
                    retain_evaluations: true,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 4],
                    retain_evaluations: true,
                },
            ],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let program = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let plan = &base.requirements().leaves.plan;
    assert_eq!(plan.lde_batches[0].columns, vec![0, 1, 2]);
    let absorbed = program
        .steps()
        .iter()
        .enumerate()
        .filter_map(|(index, step)| {
            matches!(
                step.operation,
                DomainCooperativeOperation::AbsorbDomainBatch { .. }
            )
            .then(|| program.canonical_columns_for_step(index).unwrap())
        })
        .flatten()
        .collect::<Vec<_>>();
    assert_eq!(absorbed, vec![0, 1, 2, 3]);
    let evaluations = plan
        .columns
        .iter()
        .map(|column| {
            (0..1usize << column.evaluation_log_size)
                .map(|row| 17 + 101 * column.canonical_index as u32 + row as u32)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        progressive_leaf_oracle(plan, &evaluations).unwrap(),
        full_lifting_leaf_oracle(plan, &evaluations).unwrap()
    );
}

#[test]
fn unretained_outputs_are_rejected_instead_of_aliasing_shared_scratch() {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 6,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![3, 4],
                retain_evaluations: false,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    assert_eq!(
        DomainCooperativeProgram::compile_mode_a(&base),
        Err(DomainCooperativeProgramError::RequiresRetainedEvaluations {
            canonical_column: 0
        })
    );
}

#[test]
fn schedule_pending_and_state_slice_mutations_fail_closed() {
    let base = base_program(&[3; 17].into_iter().chain([4; 17]).collect::<Vec<_>>(), 6);
    let canonical = DomainCooperativeProgram::compile_mode_a(&base).unwrap();

    let mut swapped = canonical.clone();
    let indices = swapped
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| {
            matches!(
                step.operation,
                DomainCooperativeOperation::AbsorbDomainBatch { .. }
            )
            .then_some(index)
        })
        .collect::<Vec<_>>();
    swapped.steps.swap(indices[0], indices[1]);
    assert_eq!(
        swapped.validate_against(&base),
        Err(DomainCooperativeProgramError::NonCanonicalProgram)
    );

    let mut pending = canonical.clone();
    let step = pending
        .steps
        .iter_mut()
        .find(|step| {
            matches!(
                step.operation,
                DomainCooperativeOperation::AbsorbDomainBatch { .. }
            )
        })
        .unwrap();
    if let DomainCooperativeOperation::AbsorbDomainBatch {
        pending_after_words,
        ..
    } = &mut step.operation
    {
        *pending_after_words ^= 1;
    }
    assert_eq!(
        pending.validate_against(&base),
        Err(DomainCooperativeProgramError::NonCanonicalProgram)
    );

    let mut aliased = canonical.clone();
    let step = aliased
        .steps
        .iter_mut()
        .find(|step| {
            matches!(
                step.operation,
                DomainCooperativeOperation::AbsorbDomainBatch { .. }
            )
        })
        .unwrap();
    if let DomainCooperativeOperation::AbsorbDomainBatch { state, .. } = &mut step.operation {
        state.offset_words = 1;
    }
    assert_eq!(
        aliased.validate_against(&base),
        Err(DomainCooperativeProgramError::NonCanonicalProgram)
    );
}

#[test]
fn seeded_128_shape_oracle_matches_leaves_roots_and_one_word_mutations() {
    let mut seed = 0x6a09_e667u32;
    for case in 0..128usize {
        let columns = 1 + (next(&mut seed) as usize % 65);
        let mut logs = (0..columns)
            .map(|_| 3 + next(&mut seed) % 4)
            .collect::<Vec<_>>();
        logs.sort_unstable();
        let base = base_program(&logs, 8);
        let program = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
        program.validate_against(&base).unwrap();
        let plan = &base.requirements().leaves.plan;
        let mut evaluations = plan
            .columns
            .iter()
            .map(|column| {
                (0..1usize << column.evaluation_log_size)
                    .map(|row| {
                        next(&mut seed)
                            .wrapping_add(row as u32)
                            .wrapping_add(column.canonical_index as u32)
                            & 0x7fff_fffe
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let progressive = progressive_leaf_oracle(plan, &evaluations).unwrap();
        let full = full_lifting_leaf_oracle(plan, &evaluations).unwrap();
        assert_eq!(progressive, full, "case={case}, logs={logs:?}");
        let root = merkle_root(progressive);

        let column = next(&mut seed) as usize % evaluations.len();
        let row = next(&mut seed) as usize % evaluations[column].len();
        evaluations[column][row] ^= 1;
        let mutated = merkle_root(progressive_leaf_oracle(plan, &evaluations).unwrap());
        assert_ne!(root, mutated, "case={case}, column={column}, row={row}");

        let absorbed = program
            .steps()
            .iter()
            .enumerate()
            .filter_map(|(index, step)| {
                matches!(
                    step.operation,
                    DomainCooperativeOperation::AbsorbDomainBatch { .. }
                )
                .then(|| program.canonical_columns_for_step(index).unwrap())
            })
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(absorbed, (0..columns).collect::<Vec<_>>());
        assert_eq!(
            program.comparison().replacement_leaf_compressions,
            plan.accounting.progressive_leaf_compressions as u64
        );
    }
}

fn next(seed: &mut u32) -> u32 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 17;
    *seed ^= *seed << 5;
    *seed
}
