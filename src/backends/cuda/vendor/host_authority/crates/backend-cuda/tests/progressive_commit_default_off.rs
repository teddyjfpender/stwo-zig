//! Process-level default-off admission gate for domain-progressive commitment.

use stwo_backend_cuda::{
    progressive_leaf_workspace_requirements, progressive_leaf_workspace_requirements_for_mode,
    progressive_prepare_mode_admission, progressive_prepare_mode_admission_for_mode,
    PreparedProgressiveCommitError, PreparedProgressiveCommitGraph, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry, ProgressiveCommitMode,
};

fn geometry() -> ProgressiveCommitGeometry {
    ProgressiveCommitGeometry {
        lifting_log_size: 5,
        log_blowup_factor: 1,
        groups: vec![ProgressiveCommitGroupGeometry {
            coefficient_log_sizes: vec![4],
            retain_evaluations: false,
        }],
    }
}

#[test]
fn fully_explicit_graph_constructor_is_host_visible() {
    let _constructor = PreparedProgressiveCommitGraph::prepare_with_modes;
}

#[test]
fn env_wrapper_stays_default_off_while_explicit_mode_is_fail_closed() {
    unsafe { std::env::remove_var("STWO_CUDA_COMMIT_DOMAIN_PROGRESSIVE") };
    assert_eq!(
        ProgressiveCommitMode::from_env(),
        ProgressiveCommitMode::FullLifting
    );
    assert_eq!(
        progressive_leaf_workspace_requirements(geometry()).unwrap_err(),
        PreparedProgressiveCommitError::Disabled
    );

    // An explicitly constructed topology (the native differential seam) still
    // cannot enter `PreparedProgressiveLeaves::prepare`: this is the exact
    // admission function called before arena binding. No fallback or production
    // dispatcher is invoked by either rejection.
    let explicit = progressive_leaf_workspace_requirements_for_mode(
        ProgressiveCommitMode::DomainProgressive,
        geometry(),
    )
    .unwrap();
    assert_eq!(
        progressive_prepare_mode_admission(&explicit).unwrap_err(),
        PreparedProgressiveCommitError::Disabled
    );

    // A sealed replacement-backend selector can admit the same topology
    // without re-reading the legacy process environment.
    progressive_prepare_mode_admission_for_mode(
        ProgressiveCommitMode::DomainProgressive,
        &explicit,
    )
    .unwrap();
    assert_eq!(
        progressive_prepare_mode_admission_for_mode(ProgressiveCommitMode::FullLifting, &explicit,)
            .unwrap_err(),
        PreparedProgressiveCommitError::Disabled
    );

    let mut mismatched = explicit;
    mismatched.plan.mode = ProgressiveCommitMode::FullLifting;
    assert_eq!(
        progressive_prepare_mode_admission_for_mode(
            ProgressiveCommitMode::DomainProgressive,
            &mismatched,
        )
        .unwrap_err(),
        PreparedProgressiveCommitError::Disabled
    );
}
