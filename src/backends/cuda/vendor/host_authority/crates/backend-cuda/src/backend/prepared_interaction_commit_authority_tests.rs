use super::*;
use crate::backend::prepared_commit::CommitWorkspaceConfig;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};
use crate::backend::progressive_ntt_leaf_fusion::ProgressiveNttLeafFusionMode;

fn programs(
    coefficient_log_sizes: Vec<u32>,
) -> (
    CommitProgram,
    DirectRetainedB2nProgram,
    DirectRetainedB2nProgram,
) {
    let commit = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 3,
            max_fused_tail_levels: 0,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 6,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes,
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Separate,
        false,
    )
    .unwrap();
    let base = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit).unwrap();
    let interaction =
        DirectRetainedB2nProgram::compile(TraceTreeRole::Interaction, &commit).unwrap();
    (commit, base, interaction)
}

#[test]
fn interaction_seals_role_around_the_exact_canonical_execution() {
    let (commit, base_direct, interaction_direct) = programs(vec![3, 4, 5]);
    let base = BaseCommitProgramAuthority::compile(&commit, &base_direct).unwrap();
    let interaction =
        InteractionCommitProgramAuthority::compile(&commit, &interaction_direct).unwrap();

    interaction.validate().unwrap();
    assert_eq!(interaction.role(), TraceTreeRole::Interaction);
    assert_eq!(interaction.direct(), &interaction_direct);
    assert_eq!(interaction.commit(), base.commit());
    assert_eq!(interaction.layouts(), base.layouts());
    assert_eq!(interaction.operations(), base.operations());
    assert_eq!(
        interaction.retained_evaluations(),
        base.retained_evaluations()
    );
    assert_eq!(
        interaction.retained_layers_bottom_up(),
        base.retained_layers_bottom_up()
    );
    assert_eq!(interaction.root(), base.root());
    assert_eq!(interaction.canonical(), &base);
    assert_ne!(interaction.source_identity(), base.source_identity());
    assert_ne!(interaction.identity(), base.identity());
}

#[test]
fn role_program_and_sealed_state_drift_fail_closed() {
    let (commit, base_direct, interaction_direct) = programs(vec![3, 4, 5]);
    assert_eq!(
        InteractionCommitProgramAuthority::compile(&commit, &base_direct),
        Err(InteractionCommitAuthorityError::UnsupportedRole(
            TraceTreeRole::Base
        ))
    );

    let authority =
        InteractionCommitProgramAuthority::compile(&commit, &interaction_direct).unwrap();
    let mut role_drift = authority.clone();
    role_drift.role = TraceTreeRole::Base;
    assert_eq!(
        role_drift.validate(),
        Err(InteractionCommitAuthorityError::UnsupportedRole(
            TraceTreeRole::Base
        ))
    );

    let mut identity_drift = authority.clone();
    identity_drift.identity[0] ^= 1;
    assert_eq!(
        identity_drift.validate(),
        Err(InteractionCommitAuthorityError::ProgramMismatch)
    );

    let (other_commit, other_base, _) = programs(vec![3, 3, 5]);
    let mut program_drift = authority;
    program_drift.canonical =
        BaseCommitProgramAuthority::compile(&other_commit, &other_base).unwrap();
    assert_eq!(
        program_drift.validate(),
        Err(InteractionCommitAuthorityError::ProgramMismatch)
    );
}

#[test]
fn target_sm_link_is_role_bound_and_revalidates_exactly() {
    if !stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        return;
    }
    let (commit, base_direct, interaction_direct) = programs(vec![3, 4, 5]);
    let base = BaseCommitProgramAuthority::compile(&commit, &base_direct).unwrap();
    let interaction =
        InteractionCommitProgramAuthority::compile(&commit, &interaction_direct).unwrap();
    let target_sm = stwo_backend_cuda_kernels::static_cuda_module_target_sms()[0];
    let base_link = base.bind_static_build(target_sm).unwrap().unwrap();
    let interaction_link = interaction.bind_static_build(target_sm).unwrap().unwrap();

    interaction_link.validate(&interaction).unwrap();
    assert_eq!(interaction_link.role(), TraceTreeRole::Interaction);
    assert_eq!(interaction_link.canonical(), base_link);
    assert_eq!(
        interaction_link.module_build_identity(),
        base_link.module_build_identity()
    );
    assert_eq!(
        interaction_link.static_build_source_identity(),
        base_link.static_build_source_identity()
    );
    assert_eq!(
        interaction_link.static_build_identity(),
        base_link.static_build_identity()
    );
    assert_eq!(interaction_link.target_sm(), target_sm);
    assert_eq!(interaction_link.sm_identity(), base_link.sm_identity());
    assert_ne!(
        interaction_link.program_identity(),
        base_link.program_identity()
    );
    assert_ne!(interaction_link.identity(), base_link.identity());

    let mut tampered = interaction_link;
    tampered.identity[0] ^= 1;
    assert_eq!(
        tampered.validate(&interaction),
        Err(InteractionCommitAuthorityError::Canonical(
            BaseCommitAuthorityError::StaticBuildMismatch
        ))
    );
}
