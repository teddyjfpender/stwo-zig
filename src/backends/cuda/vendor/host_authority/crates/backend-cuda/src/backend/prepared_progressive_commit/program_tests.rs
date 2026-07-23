use super::*;
use crate::backend::progressive_commit::{merkle_root, ProgressiveCommitGroupGeometry};

fn program(interior4_fused: bool) -> CommitProgram {
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
        interior4_fused,
    )
    .unwrap()
}

fn ntt_traffic_program(fusion: ProgressiveNttLeafFusionMode) -> CommitProgram {
    let mut coefficient_log_sizes = vec![3; 16];
    coefficient_log_sizes.extend([12; 16]);
    CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 13,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 13,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes,
                retain_evaluations: false,
            }],
        },
        fusion,
        true,
    )
    .unwrap()
}

#[test]
fn manifest_seals_one_slab_and_legal_interior4_boundary() {
    let program = program(true);
    assert_eq!(
        program.identity().storage,
        ProgressiveCommitStorageMode::InPlaceSlab
    );
    assert_eq!(
        program.retained_layers_bottom_up(),
        [
            CommitProgramLayer {
                log_size: 2,
                words: 4 * HASH_WORDS,
            },
            CommitProgramLayer {
                log_size: 1,
                words: 2 * HASH_WORDS,
            },
            CommitProgramLayer {
                log_size: 0,
                words: HASH_WORDS,
            },
        ]
    );
    assert_eq!(
        program
            .steps()
            .iter()
            .filter(|step| matches!(
                step.operation,
                CommitProgramOperation::MerkleInterior4 {
                    first_level: 0,
                    output_hashes: 4
                }
            ))
            .count(),
        1
    );
    assert!(!program.steps().iter().any(|step| matches!(
        step.operation,
        CommitProgramOperation::MerkleLayerInPlace { .. }
    )));
    assert_eq!(
        program.in_place_slab_words().unwrap(),
        64 * STATE_WORDS + PROGRESSIVE_IN_PLACE_SCRATCH_WORDS
    );
}

#[test]
fn disabling_interior4_exposes_the_exact_destructive_suboperations() {
    let fused = program(true);
    let scalar = program(false);
    assert_ne!(fused.identity().cache_key, scalar.identity().cache_key);
    assert_eq!(
        scalar
            .steps()
            .iter()
            .filter(|step| matches!(
                step.operation,
                CommitProgramOperation::MerkleLayerInPlace { .. }
            ))
            .count(),
        3
    );
    assert!(scalar.traffic().kernel_launches > fused.traffic().kernel_launches);
    assert!(scalar.traffic().device_copies > fused.traffic().device_copies);
    assert!(
        scalar.traffic().total_owned_bytes().unwrap()
            > fused.traffic().total_owned_bytes().unwrap()
    );
}

#[test]
fn fused_manifest_resolves_canonical_membership_and_exact_nested_ntt_traffic() {
    let program = ntt_traffic_program(ProgressiveNttLeafFusionMode::Fused16);
    let (index, step) = program
        .steps()
        .iter()
        .enumerate()
        .find(|(_, step)| {
            matches!(
                step.operation,
                CommitProgramOperation::FusedLdeAbsorb16 {
                    batch_index: 1,
                    segment_offset: 0,
                    log_size: 13,
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(
        program.canonical_columns_for_step(index).unwrap(),
        (16..32).collect::<Vec<_>>()
    );
    assert_eq!(
        step.traffic,
        CommitProgramTraffic {
            owned_read_bytes: 1_835_008,
            owned_write_bytes: 1_835_008,
            kernel_launches: 3,
            device_copies: 0,
        }
    );
}

#[test]
fn separate_manifest_counts_stage_ntt_and_absorb_traffic_exactly() {
    let program = ntt_traffic_program(ProgressiveNttLeafFusionMode::Separate);
    let (lde_index, lde) = program
        .steps()
        .iter()
        .enumerate()
        .find(|(_, step)| {
            matches!(
                step.operation,
                CommitProgramOperation::Lde {
                    batch_index: 1,
                    segment_offset: 0,
                    columns: 16,
                    log_size: 13,
                }
            )
        })
        .unwrap();
    assert_eq!(
        program.canonical_columns_for_step(lde_index).unwrap(),
        (16..32).collect::<Vec<_>>()
    );
    assert_eq!(
        lde.traffic,
        CommitProgramTraffic {
            owned_read_bytes: 1_048_576,
            owned_write_bytes: 1_572_864,
            kernel_launches: 3,
            device_copies: 0,
        }
    );
    let absorb = program
        .steps()
        .iter()
        .find(|step| {
            matches!(
                step.operation,
                CommitProgramOperation::Absorb {
                    batch_index: 1,
                    segment_offset: 0,
                    columns: 16,
                    log_size: 13,
                    ..
                }
            )
        })
        .unwrap();
    assert_eq!(
        absorb.traffic,
        CommitProgramTraffic {
            owned_read_bytes: 1_310_720,
            owned_write_bytes: 786_432,
            kernel_launches: 1,
            device_copies: 0,
        }
    );
}

#[test]
fn separate_lde_chunk_boundary_repeats_stage_and_ntt_phases() {
    assert_eq!(lde_kernel_launches(13, 65_535).unwrap(), 3);
    assert_eq!(lde_kernel_launches(13, 65_536).unwrap(), 6);
}

#[test]
fn deterministic_fixture_preserves_leaves_retained_order_and_root() {
    let program = program(true);
    let fixture = program.fixture(0x51ab_1e55).unwrap();
    assert_eq!(fixture.seed, 0x51ab_1e55);
    assert_eq!(
        fixture
            .oracle
            .retained_layers_bottom_up
            .iter()
            .map(|layer| layer.log_size)
            .collect::<Vec<_>>(),
        [2, 1, 0]
    );
    assert_eq!(
        fixture.oracle.root,
        merkle_root(fixture.oracle.leaf_hashes.clone())
    );
    assert_eq!(
        fixture
            .oracle
            .retained_layers_bottom_up
            .last()
            .unwrap()
            .hashes,
        vec![fixture.oracle.root]
    );
    assert_eq!(program.fixture(0x51ab_1e55).unwrap(), fixture);
    assert_ne!(
        program.fixture(0x51ab_1e56).unwrap().oracle.root,
        fixture.oracle.root
    );
}

#[test]
fn in_place_program_fails_closed_when_leaf_layer_is_retained() {
    assert_eq!(
        CommitProgram::compile(
            CommitWorkspaceConfig {
                log_blowup_factor: 1,
                lifting_log_size: 6,
                unretained_bottom_layers: 0,
                max_fused_tail_levels: 2,
            },
            ProgressiveCommitGeometry {
                lifting_log_size: 6,
                log_blowup_factor: 1,
                groups: vec![ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![5],
                    retain_evaluations: false,
                }],
            },
            ProgressiveNttLeafFusionMode::Fused16,
            true,
        ),
        Err(CommitProgramError::InvalidInPlaceConfiguration)
    );
}
