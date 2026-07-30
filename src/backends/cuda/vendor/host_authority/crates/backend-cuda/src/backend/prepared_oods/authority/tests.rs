use super::*;

fn fixture() -> (OodsWorkspaceConfig, Vec<OodsExecutionColumn>) {
    let config = OodsWorkspaceConfig {
        lifting_log_size: 24,
        mask_log_size: 12,
    };
    let topologies = [
        OodsColumnTopology::signed_offsets(11, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0, 1]),
        OodsColumnTopology::evaluation_signed_offsets(8, &[0]),
        OodsColumnTopology::evaluation_signed_offsets(10, &[0]),
    ];
    let program = OodsPassCollapseProgram::compile(config, &topologies).unwrap();
    let authority = OodsExecutionAuthority::compile(config, &topologies, &program).unwrap();
    (config, authority.columns().to_vec())
}

fn authority() -> OodsExecutionAuthority {
    let (config, columns) = fixture();
    let topologies = columns
        .iter()
        .map(OodsExecutionColumn::topology)
        .collect::<Vec<_>>();
    let program = OodsPassCollapseProgram::compile(config, &topologies).unwrap();
    OodsExecutionAuthority::compile(config, &topologies, &program).unwrap()
}

#[test]
fn aggregate_authority_seals_exact_collapsed_mixed_execution() {
    let authority = authority();
    authority.validate().unwrap();
    assert_eq!(authority.host_calls().len(), 12);
    assert_eq!(authority.child_launch_count(), 15);
    assert_eq!(
        authority.child_launch_count(),
        authority
            .program()
            .receipt()
            .collapsed_total_kernel_launches
    );
    assert_eq!(
        authority
            .host_calls()
            .iter()
            .filter(|call| matches!(call.kind, OodsExecutionHostCallKind::EvaluateMany { .. }))
            .count(),
        3
    );
    assert!(authority
        .host_calls()
        .iter()
        .filter(|call| matches!(call.kind, OodsExecutionHostCallKind::EvaluateMany { .. }))
        .all(|call| call.children.len() == 2));
    assert_eq!(authority.invocation().arguments.len(), 16);
    assert_eq!(
        authority
            .values()
            .iter()
            .find(|value| value.role == OodsExecutionValueRole::SourcePointers)
            .unwrap()
            .ownership,
        OodsExecutionValueOwnership::PreparedRelocation
    );
    assert!(!authority
        .accesses()
        .iter()
        .any(|access| access.role == OodsExecutionValueRole::SourcePointers));
    assert_eq!(
        authority
            .accesses()
            .iter()
            .filter(|access| matches!(access.role, OodsExecutionValueRole::Source { .. }))
            .count(),
        authority.program().identity().canonical_samples.len()
    );
    for identity in [
        authority.static_source_identity(),
        authority.wrapper_source_identity(),
        authority.source_identity(),
        authority.fixed_identity(),
        authority.abi_identity(),
        authority.effect_identity(),
        authority.launch_identity(),
        authority.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
}

#[test]
fn fixed_descriptor_words_are_semantic_and_canonical() {
    let authority = authority();
    let samples = &authority.program().identity().canonical_samples;
    assert_eq!(
        authority.fixed_offset_words(),
        samples
            .iter()
            .flat_map(|sample| [sample.offset_point.x.0, sample.offset_point.y.0])
            .collect::<Vec<_>>()
    );
    assert_eq!(
        authority.fixed_fold_words(),
        samples
            .iter()
            .map(|sample| authority.config().lifting_log_size - sample.evaluation_log_size)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        authority.fixed_output_index_words(),
        samples
            .iter()
            .map(|sample| sample.output_index as u32)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        authority.fixed_descriptor_offset_words(),
        authority
            .program()
            .identity()
            .evaluation_groups
            .iter()
            .map(|group| group.descriptor_offset as u32)
            .collect::<Vec<_>>()
    );
}

#[test]
fn validation_rejects_manifest_and_identity_tampering() {
    let authority = authority();
    let mut changed = authority.clone();
    changed.host_calls[0].children[0].grid[0] += 1;
    assert_eq!(
        changed.validate(),
        Err(OodsExecutionAuthorityError::ContractMismatch)
    );

    let mut changed = authority.clone();
    changed.accesses[0].words -= 1;
    assert_eq!(
        changed.validate(),
        Err(OodsExecutionAuthorityError::ContractMismatch)
    );

    let mut changed = authority;
    changed.identity[0] ^= 1;
    assert_eq!(
        changed.validate(),
        Err(OodsExecutionAuthorityError::ContractMismatch)
    );
}

#[test]
fn compile_rejects_program_for_another_topology() {
    let config = OodsWorkspaceConfig {
        lifting_log_size: 24,
        mask_log_size: 12,
    };
    let original = [OodsColumnTopology::evaluation_signed_offsets(8, &[0])];
    let changed = [OodsColumnTopology::evaluation_signed_offsets(8, &[0, 1])];
    let program = OodsPassCollapseProgram::compile(config, &original).unwrap();
    assert!(matches!(
        OodsExecutionAuthority::compile(config, &changed, &program),
        Err(OodsExecutionAuthorityError::PassCollapse(
            OodsPassCollapseError::ProgramIdentity
        ))
    ));
}
