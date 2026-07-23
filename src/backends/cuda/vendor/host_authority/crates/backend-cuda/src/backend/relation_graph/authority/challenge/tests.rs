use super::*;

#[test]
fn expansion_contract_is_exact_and_ordered() {
    let authority = RelationChallengeExpansionAuthority::compile(37).unwrap();
    authority.validate().unwrap();
    assert_eq!(authority.drawn_words(), 8);
    assert_eq!(authority.alpha_words().unwrap(), 148);
    assert_eq!(authority.z_words(), 4);
    assert_eq!(
        authority
            .invocation()
            .iter()
            .map(|argument| argument.ordinal)
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4]
    );
    assert_eq!(
        authority.accesses(),
        [
            access(
                RelationChallengeValueRole::DrawnZAlpha,
                RelationChallengeAccessKind::Read,
                8,
            ),
            access(
                RelationChallengeValueRole::AlphaPowers,
                RelationChallengeAccessKind::Write,
                148,
            ),
            access(
                RelationChallengeValueRole::ChallengeZ,
                RelationChallengeAccessKind::Write,
                4,
            ),
        ]
    );
    let child = authority.child();
    assert_eq!(child.symbol, "relation_expand_challenges_kernel");
    assert_eq!(child.grid, [1, 1, 1]);
    assert_eq!(child.block, [1, 1, 1]);
    assert_eq!(child.dynamic_shared_bytes, 0);
    assert!(!child.cooperative);
    assert_eq!(child.accesses, authority.accesses());
    for identity in [
        authority.source_identity(),
        authority.abi_identity(),
        authority.effect_identity(),
        authority.launch_identity(),
        authority.identity(),
    ] {
        assert_ne!(identity, ZERO_IDENTITY);
    }
}

#[test]
fn zero_width_and_contract_tampering_fail_closed() {
    assert_eq!(
        RelationChallengeExpansionAuthority::compile(0),
        Err(RelationChallengeAuthorityError::ZeroAlphaPowers)
    );
    let mut changed = RelationChallengeExpansionAuthority::compile(37).unwrap();
    changed.child.grid[0] = 2;
    assert_eq!(
        changed.validate(),
        Err(RelationChallengeAuthorityError::ContractMismatch)
    );
    let mut changed = RelationChallengeExpansionAuthority::compile(37).unwrap();
    changed.accesses[0].words = 7;
    assert_eq!(
        changed.validate(),
        Err(RelationChallengeAuthorityError::ContractMismatch)
    );
    assert_ne!(
        RelationChallengeExpansionAuthority::compile(37)
            .unwrap()
            .identity(),
        RelationChallengeExpansionAuthority::compile(38)
            .unwrap()
            .identity()
    );
}

#[test]
fn linked_build_rejects_a_different_supported_target() {
    use crate::backend::prepared_witness_input::static_build::binding_for_test;

    let authority = RelationChallengeExpansionAuthority::compile(37).unwrap();
    let build = [5u8; 32];
    let target_sms = [86, 89, 90];
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        authority.identity(),
        build,
        build,
        &target_sms,
        90,
    )
    .unwrap();
    let linked = super::linked(authority.identity(), binding);
    assert_eq!(linked.target_sm(), 90);
    assert_eq!(linked.contract_identity(), authority.identity());
    assert_eq!(
        linked.validate_for_target(&authority, 89),
        Err(RelationChallengeAuthorityError::StaticBuildMismatch)
    );
    assert_eq!(
        binding_for_test(
            STATIC_BUILD_DOMAIN,
            authority.identity(),
            build,
            build,
            &target_sms,
            120,
        ),
        Err(StaticBuildBindError::UnsupportedTargetSm(120))
    );
}
