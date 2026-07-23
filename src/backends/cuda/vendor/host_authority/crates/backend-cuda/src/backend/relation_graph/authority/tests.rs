use super::*;

fn lookup_use(
    tuple_arg: u32,
    tuple_words: u32,
    relation_id: u32,
    multiplicity_kind: RelationMultiplicityKind,
) -> RelationUseDescriptor {
    RelationUseDescriptor {
        tuple_kind: RelationTupleKind::LookupWords,
        tuple_arg,
        tuple_words,
        relation_id,
        multiplicity_kind,
        multiplicity_arg: 0,
        negative: false,
    }
}

fn exact_program() -> RelationKernelProgram {
    RelationKernelProgram {
        relation_graph_hash: 0xfeed_beef,
        template_use_count: 4,
        max_alpha_powers: 8,
        batches: vec![
            RelationBatchProgram {
                source_layout: RelationSourceLayout::LookupWords { words: 8 },
                columns: vec![
                    RelationColumnDescriptor {
                        uses: vec![lookup_use(0, 3, 1, RelationMultiplicityKind::One)],
                    },
                    RelationColumnDescriptor {
                        uses: vec![
                            lookup_use(3, 2, 2, RelationMultiplicityKind::One),
                            lookup_use(5, 2, 3, RelationMultiplicityKind::Enabler),
                        ],
                    },
                ],
                instances: vec![
                    RelationRowExtent::Exact {
                        n_real_rows: 6,
                        padded_rows: 8,
                        source_offset_rows: 0,
                    },
                    RelationRowExtent::Exact {
                        n_real_rows: 8,
                        padded_rows: 8,
                        source_offset_rows: 0,
                    },
                ],
            },
            RelationBatchProgram {
                source_layout: RelationSourceLayout::ProjectedColumns { columns: 3 },
                columns: vec![RelationColumnDescriptor {
                    uses: vec![RelationUseDescriptor {
                        tuple_kind: RelationTupleKind::ProjectedColumns,
                        tuple_arg: 0,
                        tuple_words: 4,
                        relation_id: 4,
                        multiplicity_kind: RelationMultiplicityKind::Enabler,
                        multiplicity_arg: 0,
                        negative: true,
                    }],
                }],
                instances: vec![RelationRowExtent::Exact {
                    n_real_rows: 3,
                    padded_rows: 4,
                    source_offset_rows: 0,
                }],
            },
        ],
    }
}

fn compile(program: &RelationKernelProgram) -> RelationExecutionAuthority {
    let requirements = program
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    RelationExecutionAuthority::compile(
        program,
        &requirements,
        RelationLaunchMode::Fused,
        RelationTailMode::Segmented,
    )
    .unwrap()
}

#[test]
fn exact_fused_segmented_manifest_is_complete_and_ordered() {
    let program = exact_program();
    let authority = compile(&program);
    authority.validate().unwrap();
    assert_eq!(authority.instances().len(), 3);
    assert_eq!(authority.eligibility_mask(), [7, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(authority.descriptor_words().len(), 3 * DESCRIPTOR_WORDS);
    assert_eq!(
        authority.geometry_words().len(),
        3 * INSTANCE_GEOMETRY_WORDS
    );
    assert_eq!(authority.values().len(), 52);

    let instances = authority.instances();
    assert_eq!(
        &instances[0].geometry[..10],
        &[0, 2, 0, 1, 0, 1, 8, 2, 6, 0]
    );
    assert_eq!(
        &instances[1].geometry[..10],
        &[2, 2, 1, 1, 1, 1, 8, 2, 8, 0]
    );
    assert_eq!(
        &instances[2].geometry[..10],
        &[4, 1, 2, 1, 2, 1, 4, 1, 3, 0]
    );

    let [body, tail] = authority.wrappers();
    assert_eq!(body.stage, RelationExecutionStage::FusedBody);
    assert_eq!(body.abi, RelationAbi::FusedBodyV1);
    assert_eq!(body.invocation.arguments.len(), 11);
    assert_eq!(body.partition, RelationPartitionAuthority::Monolithic);
    assert_eq!(body.children.len(), 1);
    assert_eq!(body.children[0].symbol, "relation_fused_kernel");
    assert_eq!(body.children[0].grid, [3, 1, 1]);
    assert_eq!(body.children[0].block, [256, 1, 1]);
    assert_eq!(body.children[0].dynamic_shared_bytes, 24_560);
    assert_eq!(body.children[0].arguments.len(), 8);
    assert_eq!(body.children[0].accesses.len(), 40);
    assert_eq!(body.accesses, body.children[0].accesses);
    assert!(matches!(
        body.invocation.arguments[9].value,
        RelationInvocationValue::HostMask([7, 0, 0, 0, 0, 0, 0, 0])
    ));
    assert!(matches!(
        body.children[0].arguments[7].value,
        RelationKernelArgumentValue::Mask([7, 0, 0, 0, 0, 0, 0, 0])
    ));
    assert_eq!(
        body.invocation
            .arguments
            .iter()
            .filter(|argument| matches!(argument.value, RelationInvocationValue::HostMask(_)))
            .count(),
        1
    );
    assert_eq!(
        body.abi.arguments()[9],
        RelationAbiArgument {
            ordinal: 9,
            name: "eligible_mask_words",
            kind: RelationAbiArgumentKind::HostConstPointerU32,
            access: RelationAbiAccess::CopyHostEligibilityMaskByValue,
        }
    );
    assert!(
        authority.values().iter().all(|value| {
            body.accesses
                .iter()
                .filter(|access| access.role == value.role)
                .all(|access| {
                    access.kind != RelationAccessKind::Read
                        || value.ownership != RelationValueOwnership::ReservedUnused
                })
        }),
        "the host mask has no RelationValueRole and reserved values have no read effect"
    );

    assert_eq!(tail.stage, RelationExecutionStage::SegmentedTail);
    assert_eq!(tail.abi, RelationAbi::SegmentedTailV1);
    assert_eq!(tail.invocation.arguments.len(), 10);
    assert_eq!(tail.partition, RelationPartitionAuthority::Monolithic);
    assert_eq!(
        tail.children
            .iter()
            .map(|child| child.symbol)
            .collect::<Vec<_>>(),
        vec![
            "reduce_coordinates_ragged_kernel",
            "finalize_claimed_sums_ragged_kernel",
            "shift_scan_tiles_ragged_kernel",
            "scan_block_totals_ragged_kernel",
            "add_scan_offsets_ragged_kernel",
        ]
    );
    assert_eq!(
        tail.children
            .iter()
            .map(|child| child.grid[0])
            .collect::<Vec<_>>(),
        vec![3, 3, 12, 12, 12]
    );
    assert_eq!(
        tail.children
            .iter()
            .map(|child| child.dynamic_shared_bytes)
            .collect::<Vec<_>>(),
        vec![4096, 4096, 1024, 0, 0]
    );
    assert_eq!(
        tail.accesses,
        tail.children
            .iter()
            .flat_map(|child| child.accesses.iter().copied())
            .collect::<Vec<_>>()
    );
    for identity in [
        authority.static_source_identity(),
        authority.wrapper_source_identity(),
        authority.source_identity(),
        authority.program_identity(),
        authority.requirements_identity(),
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
fn value_roles_cover_sources_metadata_outputs_scratch_and_unused_reservations() {
    let authority = compile(&exact_program());
    let value = |role| {
        authority
            .values()
            .iter()
            .find(|value| value.role == role)
            .copied()
            .unwrap()
    };
    assert_eq!(
        value(RelationValueRole::InstanceSource {
            batch: 0,
            instance: 0,
            source: 0,
        }),
        RelationValueLayout {
            role: RelationValueRole::InstanceSource {
                batch: 0,
                instance: 0,
                source: 0,
            },
            words: 64,
            alignment_words: 1,
            ownership: RelationValueOwnership::ExternalSource,
        }
    );
    assert!(value(RelationValueRole::InstanceSource {
        batch: 0,
        instance: 0,
        source: 0,
    })
    .ownership
    .is_causal_external_input());
    assert_eq!(
        value(RelationValueRole::AlphaPowers).ownership,
        RelationValueOwnership::TranscriptChallenge
    );
    assert!(value(RelationValueRole::AlphaPowers)
        .ownership
        .is_causal_external_input());
    assert_eq!(
        value(RelationValueRole::Descriptors).ownership,
        RelationValueOwnership::PreparedMetadata
    );
    assert_eq!(
        value(RelationValueRole::OutputCoordinate {
            batch: 1,
            instance: 0,
            coordinate: 3,
        })
        .ownership,
        RelationValueOwnership::ExecutionOutput
    );
    assert_eq!(
        value(RelationValueRole::ReductionPartials).ownership,
        RelationValueOwnership::ExecutionScratch
    );
    for role in [
        RelationValueRole::InverseScratchUnused,
        RelationValueRole::ScanEvalScratchUnused,
        RelationValueRole::ScanTempScratchUnused,
        RelationValueRole::ScanDescriptorsUnused,
        RelationValueRole::DenominatorSentinelUnused {
            batch: 0,
            instance: 0,
        },
    ] {
        let ownership = value(role).ownership;
        assert_eq!(ownership, RelationValueOwnership::ReservedUnused);
        assert!(!ownership.is_causal_external_input());
    }
}

#[test]
fn body_and_tail_effects_seal_the_exact_dependency_boundary() {
    let authority = compile(&exact_program());
    let body = &authority.wrappers()[0].children[0];
    assert!(body.accesses.iter().any(|access| {
        access.role == RelationValueRole::ChallengeZ
            && access.kind == RelationAccessKind::Read
            && access.words == SECURE_FIELD_WORDS
    }));
    assert!(body.accesses.iter().any(|access| {
        access.role
            == RelationValueRole::OutputCoordinate {
                batch: 0,
                instance: 1,
                coordinate: 7,
            }
            && access.kind == RelationAccessKind::Write
            && access.words == 8
    }));
    assert!(!body.accesses.iter().any(|access| {
        matches!(
            access.role,
            RelationValueRole::DenominatorSentinelUnused { .. }
                | RelationValueRole::InverseScratchUnused
        )
    }));
    assert_eq!(
        body.accesses
            .iter()
            .filter(|access| {
                matches!(
                    access.role,
                    RelationValueRole::DenominatorSentinelUnused { .. }
                        | RelationValueRole::InverseScratchUnused
                        | RelationValueRole::ScanEvalScratchUnused
                        | RelationValueRole::ScanTempScratchUnused
                        | RelationValueRole::ScanDescriptorsUnused
                )
            })
            .count(),
        0,
        "reserved storage is neither a body dependency nor an external root"
    );

    let tail = &authority.wrappers()[1].children;
    assert!(tail[0].accesses.iter().any(|access| {
        access.role == RelationValueRole::ReductionPartials
            && access.kind == RelationAccessKind::Write
    }));
    assert!(tail[1].accesses.iter().any(|access| {
        matches!(access.role, RelationValueRole::ClaimedSum { .. })
            && access.kind == RelationAccessKind::Write
    }));
    assert!(tail[2].accesses.iter().any(|access| {
        access.role == RelationValueRole::ScanBlockSums && access.kind == RelationAccessKind::Write
    }));
    assert!(tail[3].accesses.iter().any(|access| {
        access.role == RelationValueRole::ScanBlockSums
            && access.kind == RelationAccessKind::ReadWrite
    }));
    assert!(tail[4].accesses.iter().any(|access| {
        matches!(access.role, RelationValueRole::OutputCoordinate { .. })
            && access.kind == RelationAccessKind::ReadWrite
    }));
}

#[test]
fn mode_tail_requirements_and_empty_execution_drift_fail_closed() {
    let program = exact_program();
    let requirements = program
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert_eq!(
        RelationExecutionAuthority::compile(
            &program,
            &requirements,
            RelationLaunchMode::ThreeStage,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::UnsupportedLaunchMode(
            RelationLaunchMode::ThreeStage
        ))
    );
    assert_eq!(
        RelationExecutionAuthority::compile(
            &program,
            &requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Scan,
        ),
        Err(RelationExecutionAuthorityError::UnsupportedTailMode(
            RelationTailMode::Scan
        ))
    );

    let mut stale = requirements.clone();
    stale.reduction_words += SECURE_FIELD_WORDS;
    assert_eq!(
        RelationExecutionAuthority::compile(
            &program,
            &stale,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::NonCanonicalRequirements)
    );

    let mut empty = program;
    for batch in &mut empty.batches {
        batch.instances.clear();
    }
    let requirements = empty
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert_eq!(
        RelationExecutionAuthority::compile(
            &empty,
            &requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::EmptyExecution)
    );
}

#[test]
fn bounded_blake_and_generic_fallback_require_separate_authorities() {
    let mut bounded = exact_program();
    bounded.batches[0].instances[0] = RelationRowExtent::Bounded {
        observed_rows: 6,
        max_rows: 8,
        padded_capacity: 8,
    };
    let requirements = bounded
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert_eq!(
        RelationExecutionAuthority::compile(
            &bounded,
            &requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::UnresolvedBoundedRows {
            batch: 0,
            instance: 0,
        })
    );

    let mut fallback = exact_program();
    fallback.max_alpha_powers = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
    fallback.batches[0].source_layout = RelationSourceLayout::LookupWords {
        words: RELATION_FUSED_MAX_TUPLE_WORDS + 2,
    };
    fallback.batches[0].columns[0].uses[0].tuple_words = RELATION_FUSED_MAX_TUPLE_WORDS + 1;
    let requirements = fallback
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert_eq!(
        RelationExecutionAuthority::compile(
            &fallback,
            &requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::FusedFallbackRequiresSeparateAuthority { batch: 0 })
    );

    let blake = blake_program();
    let requirements = blake
        .requirements_for_mode(RelationLaunchMode::Fused)
        .unwrap();
    assert_eq!(
        RelationExecutionAuthority::compile(
            &blake,
            &requirements,
            RelationLaunchMode::Fused,
            RelationTailMode::Segmented,
        ),
        Err(RelationExecutionAuthorityError::BlakeGRequiresSeparateAuthority { batch: 0 })
    );
}

#[test]
fn descriptor_and_manifest_tampering_change_identity_or_fail_validation() {
    let program = exact_program();
    let authority = compile(&program);
    let mut changed = program;
    changed.batches[0].columns[0].uses[0].relation_id += 1;
    let changed = compile(&changed);
    assert_ne!(authority.program_identity(), changed.program_identity());
    assert_ne!(authority.identity(), changed.identity());

    let mut tampered = authority.clone();
    tampered.eligibility_mask[0] ^= 1;
    assert_eq!(
        tampered.validate(),
        Err(RelationExecutionAuthorityError::ContractMismatch)
    );
    let mut tampered = authority.clone();
    tampered.wrappers[1].children.swap(0, 1);
    assert_eq!(
        tampered.validate(),
        Err(RelationExecutionAuthorityError::ContractMismatch)
    );
    let mut tampered = authority;
    tampered.values[0].words += 1;
    assert_eq!(
        tampered.validate(),
        Err(RelationExecutionAuthorityError::ContractMismatch)
    );
    let mut tampered = compile(&exact_program());
    tampered.source_identity[0] ^= 1;
    assert_eq!(
        tampered.validate(),
        Err(RelationExecutionAuthorityError::ContractMismatch)
    );
}

#[test]
fn static_build_binding_is_absent_or_valid_for_the_linked_target() {
    let authority = compile(&exact_program());
    let target_sm = stwo_backend_cuda_kernels::static_cuda_module_target_sms()
        .first()
        .copied()
        .unwrap_or(89);
    if let Some(linked) = authority.bind_static_build(target_sm).unwrap() {
        linked.validate(&authority).unwrap();
        assert_eq!(linked.contract_identity(), authority.identity());
        assert_eq!(linked.target_sm(), target_sm);
        for identity in [
            linked.module_build_identity(),
            linked.static_build_source_identity(),
            linked.static_build_identity(),
            linked.sm_identity(),
            linked.identity(),
        ] {
            assert_ne!(identity, ZERO_IDENTITY);
        }
    }

    use crate::backend::prepared_witness_input::static_build::binding_for_test;
    let build = [3u8; 32];
    let target_sms = [86, 89, 90];
    let binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        authority.identity(),
        build,
        build,
        &target_sms,
        89,
    )
    .unwrap();
    let linked = super::identity::linked_authority(authority.identity(), binding);
    assert_eq!(linked.target_sm(), 89);
    assert_eq!(linked.contract_identity(), authority.identity());
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

    let other_binding = binding_for_test(
        STATIC_BUILD_DOMAIN,
        authority.identity(),
        build,
        build,
        &target_sms,
        90,
    )
    .unwrap();
    let other_linked = super::identity::linked_authority(authority.identity(), other_binding);
    assert_eq!(
        other_linked.validate_for_target(&authority, 89),
        Err(RelationExecutionAuthorityError::StaticBuildMismatch),
        "a valid binding for another supported SM is not the chosen-target binding"
    );
}

fn blake_program() -> RelationKernelProgram {
    let mut use_index = 0usize;
    let columns = (0..BLAKE_G_LOGUP_COLUMNS)
        .map(|column| {
            let arity = if column < 8 { 2 } else { 1 };
            let uses = (0..arity)
                .map(|_| {
                    let final_use = use_index + 1 == BLAKE_G_RELATION_IDS.len();
                    let relation_use = RelationUseDescriptor {
                        tuple_kind: RelationTupleKind::BlakeGInputs,
                        tuple_arg: use_index as u32,
                        tuple_words: if final_use { 21 } else { 4 },
                        relation_id: BLAKE_G_RELATION_IDS[use_index],
                        multiplicity_kind: if final_use {
                            RelationMultiplicityKind::Enabler
                        } else {
                            RelationMultiplicityKind::One
                        },
                        multiplicity_arg: 0,
                        negative: final_use,
                    };
                    use_index += 1;
                    relation_use
                })
                .collect();
            RelationColumnDescriptor { uses }
        })
        .collect();
    RelationKernelProgram {
        relation_graph_hash: 0xb1a6_e601,
        template_use_count: BLAKE_G_RELATION_IDS.len(),
        max_alpha_powers: 21,
        batches: vec![RelationBatchProgram {
            source_layout: RelationSourceLayout::BlakeGInputs,
            columns,
            instances: vec![RelationRowExtent::Exact {
                n_real_rows: 6,
                padded_rows: 8,
                source_offset_rows: 0,
            }],
        }],
    }
}
