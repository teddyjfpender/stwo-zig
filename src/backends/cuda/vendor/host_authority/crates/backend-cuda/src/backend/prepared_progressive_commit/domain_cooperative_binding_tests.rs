use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

fn base_program(mode: ProgressiveNttLeafFusionMode) -> CommitProgram {
    base_program_with_interior(mode, true)
}

fn base_program_with_interior(
    mode: ProgressiveNttLeafFusionMode,
    interior_fused: bool,
) -> CommitProgram {
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
        mode,
        interior_fused,
    )
    .unwrap()
}

fn legacy_launches(base: &CommitProgram) -> Vec<ProgressiveLeafLaunchKind> {
    base.requirements()
        .leaves
        .launch_sequence()
        .into_iter()
        .map(|launch| match launch {
            ProgressiveLeafLaunchKind::Expand {
                from_log_size,
                to_log_size,
            } => ProgressiveLeafLaunchKind::ExpandInPlace {
                from_log_size,
                to_log_size,
            },
            ProgressiveLeafLaunchKind::Finalize {
                log_size,
                absorbed_columns,
            } => ProgressiveLeafLaunchKind::FinalizeInPlace {
                log_size,
                absorbed_columns,
            },
            launch => launch,
        })
        .collect()
}

#[test]
fn promotion_is_exact_and_moves_every_complete_lde_before_hashing() {
    let base = base_program(ProgressiveNttLeafFusionMode::Fused16);
    let program = admit_base(&base).unwrap();
    let legacy = legacy_launches(&base);
    let plan = promotion_plan(&program, &legacy).unwrap();
    let actual = plan
        .replacements
        .iter()
        .map(|(_, launch)| *launch)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected_domain_launches(&program).unwrap());
    assert!(!actual.iter().any(|launch| matches!(
        launch,
        ProgressiveLeafLaunchKind::Init { .. } | ProgressiveLeafLaunchKind::Absorb { .. }
    )));
    let first_non_lde = actual
        .iter()
        .position(|launch| !matches!(launch, ProgressiveLeafLaunchKind::Lde { .. }))
        .unwrap();
    assert!(actual[..first_non_lde]
        .iter()
        .all(|launch| matches!(launch, ProgressiveLeafLaunchKind::Lde { .. })));
    assert_eq!(
        actual
            .iter()
            .filter(|launch| matches!(launch, ProgressiveLeafLaunchKind::DomainAbsorb { .. }))
            .count(),
        base.requirements().leaves.plan.lde_batches.len()
    );
}

#[test]
fn missing_duplicate_and_extra_legacy_launches_fail_closed() {
    let base = base_program(ProgressiveNttLeafFusionMode::Fused16);
    let program = admit_base(&base).unwrap();
    let canonical = legacy_launches(&base);

    let mut missing = canonical.clone();
    missing.remove(
        missing
            .iter()
            .position(|launch| matches!(launch, ProgressiveLeafLaunchKind::Absorb { .. }))
            .unwrap(),
    );
    assert!(matches!(
        promotion_plan(&program, &missing),
        Err(DomainCooperativeBindingError::MissingLegacyLaunch(_))
    ));

    let mut duplicate = canonical.clone();
    let absorb = duplicate
        .iter()
        .copied()
        .find(|launch| matches!(launch, ProgressiveLeafLaunchKind::Absorb { .. }))
        .unwrap();
    duplicate.push(absorb);
    assert_eq!(
        promotion_plan(&program, &duplicate),
        Err(DomainCooperativeBindingError::DuplicateLegacyLaunch(absorb))
    );

    let mut extra = canonical;
    extra.push(ProgressiveLeafLaunchKind::Finalize {
        log_size: 7,
        absorbed_columns: 34,
    });
    assert_eq!(
        promotion_plan(&program, &extra),
        Err(DomainCooperativeBindingError::UnexpectedLegacyLaunch(
            ProgressiveLeafLaunchKind::Finalize {
                log_size: 7,
                absorbed_columns: 34,
            }
        ))
    );
}

#[test]
fn initialization_and_baseline_are_explicit_and_default_off() {
    let base = base_program(ProgressiveNttLeafFusionMode::Fused16);
    let program = admit_base(&base).unwrap();
    let mut legacy = legacy_launches(&base);
    legacy.retain(|launch| !matches!(launch, ProgressiveLeafLaunchKind::Init { .. }));
    assert_eq!(
        promotion_plan(&program, &legacy),
        Err(DomainCooperativeBindingError::MissingInitialization)
    );

    let separate = base_program(ProgressiveNttLeafFusionMode::Separate);
    assert_eq!(
        admit_base(&separate),
        Err(DomainCooperativeBindingError::RequiresFused16Baseline {
            actual: ProgressiveNttLeafFusionMode::Separate,
        })
    );
}

#[test]
fn precompiled_program_rejects_base_identity_drift() {
    let base = base_program(ProgressiveNttLeafFusionMode::Fused16);
    let program = admit_base(&base).unwrap();
    let drifted = base_program_with_interior(ProgressiveNttLeafFusionMode::Fused16, false);
    assert_eq!(
        admit_program(&program, &drifted),
        Err(DomainCooperativeBindingError::Program(
            DomainCooperativeProgramError::NonCanonicalProgram,
        ))
    );
}

#[test]
fn projection_rejects_log_31_before_native_shift() {
    let operation = DomainCooperativeOperation::AbsorbDomainBatch {
        batch_index: 0,
        first_column: 0,
        columns: 1,
        log_size: 31,
        absorbed_columns_before: 0,
        pending_before_words: 0,
        pending_after_words: 1,
        initializes_state: true,
        state: DomainCooperativeSlabSlice {
            offset_words: 0,
            len_words: 0,
        },
        leaf_compressions: 0,
    };
    assert_eq!(
        project_operation(operation, usize::MAX),
        Err(DomainCooperativeBindingError::UnsupportedLogSize(31))
    );
}
