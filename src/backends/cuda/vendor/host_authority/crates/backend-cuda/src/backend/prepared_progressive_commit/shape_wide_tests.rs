use super::*;
use crate::backend::progressive_commit::{
    full_lifting_leaf_oracle, merkle_root, progressive_leaf_oracle, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry,
};

fn program(logs: &[u32], retained: bool, lifting: u32) -> CommitProgram {
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
                retain_evaluations: retained,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap()
}

#[test]
fn exact_layout_replaces_state_without_aliasing_live_evaluations() {
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
                    coefficient_log_sizes: vec![3, 4],
                    retain_evaluations: false,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![5],
                    retain_evaluations: true,
                },
            ],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let shape = ShapeWideCommitProgram::compile_replacement_v1(&base).unwrap();
    assert_eq!(shape.materialized_evaluation_words(), 16 + 32 + 64);
    assert_eq!(shape.staged_evaluation_words(), 16 + 32);
    assert_eq!(shape.retained_evaluation_words(), 64);
    assert_eq!(shape.combined_descriptor_words(), 3 * 4);
    assert_eq!(shape.slab().leaf_hashes, 0..64 * HASH_WORDS);
    assert_eq!(
        shape.slab().staged_evaluations,
        64 * HASH_WORDS..64 * HASH_WORDS + 48
    );
    assert_eq!(
        shape.columns()[2].storage,
        ShapeWideColumnStorage::Retained {
            group: 1,
            column: 0
        }
    );
    assert!(shape.slab().staged_evaluations.end <= shape.slab().scratch.start);
    assert_eq!(
        shape.tree_working_words(),
        112 + 64 * HASH_WORDS + PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
    );
}

#[test]
fn mixed_retention_is_bound_to_each_exact_batch_descriptor_slice() {
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
                    retain_evaluations: false,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 3],
                    retain_evaluations: true,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![4],
                    retain_evaluations: false,
                },
            ],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let shape = ShapeWideCommitProgram::compile_replacement_v1(&base).unwrap();
    let stage_steps = shape
        .leaf_steps()
        .iter()
        .enumerate()
        .filter(|(_, step)| matches!(step.operation, ShapeWideLeafOperation::StageLdeBatch { .. }))
        .collect::<Vec<_>>();
    assert_eq!(stage_steps.len(), 2);
    assert_eq!(
        stage_steps[0].1.operation,
        ShapeWideLeafOperation::StageLdeBatch {
            batch_index: 0,
            first_column: 0,
            log_size: 4,
            columns: 4,
        }
    );
    assert_eq!(
        shape
            .columns_for_leaf_step(stage_steps[0].0)
            .unwrap()
            .iter()
            .map(|column| column.storage)
            .collect::<Vec<_>>(),
        vec![
            ShapeWideColumnStorage::Staged {
                offset_words: 64 * HASH_WORDS,
            },
            ShapeWideColumnStorage::Staged {
                offset_words: 64 * HASH_WORDS + 16,
            },
            ShapeWideColumnStorage::Retained {
                group: 1,
                column: 0,
            },
            ShapeWideColumnStorage::Retained {
                group: 1,
                column: 1,
            },
        ]
    );
    assert_eq!(
        shape
            .columns_for_leaf_step(stage_steps[1].0)
            .unwrap()
            .iter()
            .map(|column| (column.canonical_index, column.storage))
            .collect::<Vec<_>>(),
        vec![(
            4,
            ShapeWideColumnStorage::Staged {
                offset_words: 64 * HASH_WORDS + 32,
            },
        )]
    );
    assert_eq!(core::mem::size_of::<ShapeWideColumnDescriptorAbi>(), 16);
    assert_eq!(core::mem::align_of::<ShapeWideColumnDescriptorAbi>(), 8);
    assert_eq!(
        core::mem::offset_of!(ShapeWideColumnDescriptorAbi, column),
        0
    );
    assert_eq!(
        core::mem::offset_of!(ShapeWideColumnDescriptorAbi, evaluation_log_size),
        8
    );
    assert_eq!(
        core::mem::offset_of!(ShapeWideColumnDescriptorAbi, reserved),
        12
    );
}

#[test]
fn final_width_is_lazy_blake_exact_at_every_block_boundary() {
    for (columns, update, final_width, calls) in [
        (1usize, 0u32, 1u32, 1u32),
        (16, 0, 16, 1),
        (17, 16, 1, 2),
        (32, 16, 16, 2),
        (33, 32, 1, 2),
    ] {
        let logs = vec![3; columns];
        let shape =
            ShapeWideCommitProgram::compile_replacement_v1(&program(&logs, true, 6)).unwrap();
        let leaf = shape
            .leaf_steps()
            .iter()
            .filter(|step| !matches!(step.operation, ShapeWideLeafOperation::StageLdeBatch { .. }))
            .map(|step| step.operation)
            .collect::<Vec<_>>();
        if update == 0 {
            assert_eq!(leaf.len(), 1);
        } else {
            assert_eq!(
                leaf[0],
                ShapeWideLeafOperation::QuadUpdate { columns: update }
            );
        }
        assert_eq!(
            *leaf.last().unwrap(),
            ShapeWideLeafOperation::RemainderFinalize {
                first_column: update,
                columns: final_width,
                initializes_state: update == 0,
            }
        );
        assert_eq!(shape.comparison().replacement_state_api_calls, calls);
    }
}

#[test]
fn traffic_and_suffix_are_exact_and_independent() {
    let base = program(&vec![3; 17], true, 6);
    let shape = ShapeWideCommitProgram::compile_replacement_v1(&base).unwrap();
    let hash_bytes = 64 * HASH_BYTES;
    let update = shape
        .leaf_steps()
        .iter()
        .find(|step| matches!(step.operation, ShapeWideLeafOperation::QuadUpdate { .. }))
        .unwrap();
    assert_eq!(
        update.traffic,
        CommitProgramTraffic {
            owned_read_bytes: 64 * 16 * WORD_BYTES,
            owned_write_bytes: hash_bytes,
            kernel_launches: 1,
            device_copies: 0,
        }
    );
    let final_step = shape.leaf_steps().last().unwrap();
    assert_eq!(
        final_step.traffic,
        CommitProgramTraffic {
            owned_read_bytes: 64 * WORD_BYTES + hash_bytes,
            owned_write_bytes: hash_bytes,
            kernel_launches: 1,
            device_copies: 0,
        }
    );
    let expected_suffix = base
        .steps()
        .iter()
        .copied()
        .filter(|step| is_merkle(step.operation))
        .collect::<Vec<_>>();
    assert_eq!(shape.merkle_suffix(), expected_suffix);
    assert_eq!(
        shape.comparison().replacement_state_transition_bytes,
        2 * hash_bytes
    );
    assert!(shape.comparison().state_transition_bytes_eliminated > 0);
}

#[test]
fn excessive_native_staging_fails_before_arena_binding() {
    let base = program(&vec![5; 17], false, 6);
    assert!(matches!(
        ShapeWideCommitProgram::compile_replacement_v1(&base),
        Err(ShapeWideCommitProgramError::StagingExceedsSlab { .. })
    ));
}

#[test]
fn canonical_shape_wide_bytes_match_progressive_across_mutation() {
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
                    coefficient_log_sizes: vec![3, 3, 3],
                    retain_evaluations: false,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3, 4, 4],
                    retain_evaluations: true,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![4, 5, 5, 5],
                    retain_evaluations: false,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![5, 5, 5, 5, 5, 5, 5],
                    retain_evaluations: true,
                },
            ],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let shape = ShapeWideCommitProgram::compile_replacement_v1(&base).unwrap();
    let plan = &base.requirements().leaves.plan;
    for salt in [0u32, 1, 0x7fff_fffe, 0x5a17_91d3] {
        let evaluations = plan
            .columns
            .iter()
            .map(|column| {
                (0..1usize << column.evaluation_log_size)
                    .map(|row| {
                        salt.wrapping_add((column.canonical_index as u32).wrapping_mul(104_729))
                            ^ (row as u32).wrapping_mul(7_919)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let progressive = progressive_leaf_oracle(plan, &evaluations).unwrap();
        let full = full_lifting_leaf_oracle(plan, &evaluations).unwrap();
        assert_eq!(progressive, full);
        assert_eq!(merkle_root(progressive), merkle_root(full));
    }
    assert_eq!(
        shape.comparison().replacement_leaf_compressions,
        plan.accounting.full_lifting_leaf_compressions as u64
    );
}
