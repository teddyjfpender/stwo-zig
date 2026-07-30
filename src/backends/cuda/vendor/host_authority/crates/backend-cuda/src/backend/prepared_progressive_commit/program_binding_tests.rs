use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn program() -> CommitProgram {
    CommitProgram::compile(
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
                coefficient_log_sizes: vec![3, 4, 5],
                retain_evaluations: false,
            }],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap()
}

fn prepared_view() -> PreparedCommitProgramView {
    PreparedCommitProgramView {
        storage: ProgressiveCommitStorageMode::InPlaceSlab,
        leaf_launches: vec![
            ProgressiveLeafLaunchKind::Init { log_size: 4 },
            ProgressiveLeafLaunchKind::Lde {
                batch_index: 0,
                segment_offset: 0,
                log_size: 4,
                columns: 1,
            },
            ProgressiveLeafLaunchKind::Absorb {
                batch_index: 0,
                segment_offset: 0,
                log_size: 4,
                columns: 1,
                absorbed_columns_before: 0,
            },
            ProgressiveLeafLaunchKind::ExpandInPlace {
                from_log_size: 4,
                to_log_size: 5,
            },
            ProgressiveLeafLaunchKind::Lde {
                batch_index: 1,
                segment_offset: 0,
                log_size: 5,
                columns: 1,
            },
            ProgressiveLeafLaunchKind::Absorb {
                batch_index: 1,
                segment_offset: 0,
                log_size: 5,
                columns: 1,
                absorbed_columns_before: 1,
            },
            ProgressiveLeafLaunchKind::ExpandInPlace {
                from_log_size: 5,
                to_log_size: 6,
            },
            ProgressiveLeafLaunchKind::Lde {
                batch_index: 2,
                segment_offset: 0,
                log_size: 6,
                columns: 1,
            },
            ProgressiveLeafLaunchKind::Absorb {
                batch_index: 2,
                segment_offset: 0,
                log_size: 6,
                columns: 1,
                absorbed_columns_before: 2,
            },
            ProgressiveLeafLaunchKind::FinalizeInPlace {
                log_size: 6,
                absorbed_columns: 3,
            },
        ],
        merkle_launches: vec![
            CommitLaunchKind::FusedInterior4 {
                first_level: 0,
                output_hashes: 4,
            },
            CommitLaunchKind::FusedTail {
                first_hashes: 4,
                levels: 2,
            },
        ],
        retained_evaluation_words: vec![None; 3],
        retained_layer_words_bottom_up: vec![4 * HASH_WORDS, 2 * HASH_WORDS, HASH_WORDS],
        root_is_last_retained_layer: true,
    }
}

#[test]
fn exact_prepared_view_binds_all_calls_nested_counts_and_destinations() {
    let program = program();
    let view = prepared_view();
    program.validate_prepared_view(&view).unwrap();
    let actual = prepared_steps(&program, &view).unwrap();
    assert_eq!(actual, program.steps());
    assert_eq!(
        actual
            .iter()
            .find(|step| matches!(
                step.operation,
                CommitProgramOperation::MerkleInterior4 { .. }
            ))
            .unwrap()
            .traffic,
        CommitProgramTraffic {
            owned_read_bytes: 2_048,
            owned_write_bytes: 128,
            kernel_launches: 1,
            device_copies: 0,
        }
    );
}

#[test]
fn binding_rejects_canonical_membership_storage_and_root_drift() {
    let program = program();

    let mut wrong_segment = prepared_view();
    let ProgressiveLeafLaunchKind::Lde { segment_offset, .. } = &mut wrong_segment.leaf_launches[1]
    else {
        unreachable!()
    };
    *segment_offset = 1;
    assert!(matches!(
        program.validate_prepared_view(&wrong_segment),
        Err(CommitProgramBindingError::StepOperation { index: 1, .. })
    ));

    let mut wrong_storage = prepared_view();
    wrong_storage.storage = ProgressiveCommitStorageMode::Separate;
    assert!(matches!(
        program.validate_prepared_view(&wrong_storage),
        Err(CommitProgramBindingError::StorageMode { .. })
    ));

    let mut wrong_root = prepared_view();
    wrong_root.root_is_last_retained_layer = false;
    assert_eq!(
        program.validate_prepared_view(&wrong_root),
        Err(CommitProgramBindingError::RootDestination)
    );
}
