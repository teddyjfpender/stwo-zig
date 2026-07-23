use super::compiler::{
    b2n_columns_to_retained_launches, n2b_from_stage_two_launches, ntt_column_chunks,
};
use super::effect::{direct_n2b_effect, state_absorb_effect};
use super::encoding::{authority_sources, hash_operation, hash_role, source_identity_from_parts};
use super::*;
use crate::backend::progressive_commit::{
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
};

#[path = "base_commit_authority/manifest_tests.rs"]
mod manifest_tests;

fn programs(
    fusion: ProgressiveNttLeafFusionMode,
    interior4_fused: bool,
    tail_levels: u32,
) -> (CommitProgram, DirectRetainedB2nProgram) {
    let commit = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 6,
            unretained_bottom_layers: 3,
            max_fused_tail_levels: tail_levels,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 6,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![3, 4, 5],
                retain_evaluations: true,
            }],
        },
        fusion,
        interior4_fused,
    )
    .unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit).unwrap();
    (commit, direct)
}

fn operation_digest(operation: &BaseCommitOperationKind) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_operation(&mut hasher, operation).unwrap();
    *hasher.finalize().as_bytes()
}

fn role_digest(role: BaseCommitValueRole) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_role(&mut hasher, role);
    *hasher.finalize().as_bytes()
}

#[test]
fn exact_program_emits_decomposed_direct_state_and_merkle_order() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    authority.validate().unwrap();

    assert_ne!(authority.source_identity(), [0; 32]);
    assert_ne!(authority.identity(), [0; 32]);
    assert_eq!(
        authority.commit_operation_view().unwrap(),
        commit
            .steps()
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>()
    );
    assert_eq!(authority.retained_evaluations().len(), 3);
    assert_eq!(
        authority
            .retained_layers_bottom_up()
            .last()
            .unwrap()
            .log_size,
        0
    );
    assert_eq!(
        authority.root(),
        BaseCommitValueRole::HashLayer { log_size: 0 }
    );

    let kinds = authority
        .operations()
        .iter()
        .map(|operation| &operation.kind)
        .collect::<Vec<_>>();
    assert!(matches!(
        kinds[0],
        BaseCommitOperationKind::StateInit { .. }
    ));
    for batch in direct.batches() {
        let b2n = kinds.iter().position(|kind| matches!(
            kind,
            BaseCommitOperationKind::DirectB2n { batch_index, .. } if *batch_index == batch.batch_index
        )).unwrap();
        assert!(matches!(
            kinds[b2n + 1],
            BaseCommitOperationKind::DirectN2b { batch_index, .. } if *batch_index == batch.batch_index
        ));
        assert!(matches!(
            kinds[b2n + 2],
            BaseCommitOperationKind::StateAbsorb { batch_index, .. } if *batch_index == batch.batch_index
        ));
        let n2b = authority
            .operations()
            .get(b2n + 1)
            .expect("N2B immediately follows B2N");
        assert_eq!(
            n2b.abi.wrapper_symbol(),
            "stwo_ntt_n2b_columns_from_stage_two_on"
        );
        assert_eq!(
            n2b.execution
                .iter()
                .filter(|step| matches!(step, BaseCommitExecutionStep::KernelLaunch(_)))
                .count() as u32,
            n2b_from_stage_two_launches(
                batch.retained_log_size,
                u32::try_from(batch.canonical_columns.len()).unwrap(),
            )
            .unwrap()
        );
    }
}

#[test]
fn direct_b2n_launch_count_tracks_physical_dispatch_boundaries() {
    for (log_size, launches) in [
        (3, 3),
        (12, 12),
        (13, 2),
        (18, 2),
        (19, 3),
        (24, 3),
        (25, 4),
        (29, 4),
        (30, 30),
    ] {
        assert_eq!(
            b2n_columns_to_retained_launches(log_size, 1),
            Ok(launches),
            "log_size={log_size}"
        );
    }
    for log_size in [0, 1, 2, 31, u32::MAX] {
        assert_eq!(
            b2n_columns_to_retained_launches(log_size, 1),
            Err(BaseCommitAuthorityError::SizeOverflow),
            "log_size={log_size}"
        );
    }
}

#[test]
fn stage_two_n2b_launch_count_tracks_physical_dispatch_boundaries() {
    for (log_size, launches) in [
        (3, 2),
        (12, 11),
        (13, 2),
        (19, 2),
        (20, 3),
        (27, 3),
        (28, 4),
        (30, 4),
    ] {
        assert_eq!(
            n2b_from_stage_two_launches(log_size, 1),
            Ok(launches),
            "log_size={log_size}"
        );
    }
    for log_size in [0, 1, 2, 31, u32::MAX] {
        assert_eq!(
            n2b_from_stage_two_launches(log_size, 1),
            Err(BaseCommitAuthorityError::SizeOverflow),
            "log_size={log_size}"
        );
    }
}

#[test]
fn direct_ntt_launch_counts_include_checked_column_tiling() {
    assert_eq!(ntt_column_chunks(65_535), Ok(1));
    assert_eq!(ntt_column_chunks(65_536), Ok(2));
    assert_eq!(ntt_column_chunks(u32::MAX), Ok(65_537));
    assert_eq!(
        ntt_column_chunks(0),
        Err(BaseCommitAuthorityError::SizeOverflow)
    );
    assert_eq!(b2n_columns_to_retained_launches(12, 65_535), Ok(12));
    assert_eq!(b2n_columns_to_retained_launches(12, 65_536), Ok(24));
    assert_eq!(n2b_from_stage_two_launches(12, 65_535), Ok(11));
    assert_eq!(n2b_from_stage_two_launches(12, 65_536), Ok(22));
}

#[test]
fn canonical_operation_and_role_encodings_are_tagged_and_field_sensitive() {
    let operation = BaseCommitOperationKind::StateAbsorb {
        batch_index: 7,
        segment_offset: 0,
        log_size: 11,
        absorbed_columns_before: 13,
        canonical_columns: vec![2, 5],
    };
    let mut expected = blake3::Hasher::new();
    expected.update(&[5]);
    expected.update(&7u32.to_le_bytes());
    expected.update(&0u32.to_le_bytes());
    expected.update(&11u32.to_le_bytes());
    expected.update(&13u32.to_le_bytes());
    expected.update(&2u64.to_le_bytes());
    expected.update(&2u32.to_le_bytes());
    expected.update(&5u32.to_le_bytes());
    assert_eq!(
        operation_digest(&operation),
        *expected.finalize().as_bytes()
    );

    let operations = [
        BaseCommitOperationKind::DirectB2n {
            batch_index: 1,
            segment_offset: 0,
            source_log_size: 8,
            retained_log_size: 9,
            canonical_columns: vec![2, 3],
        },
        BaseCommitOperationKind::DirectB2n {
            batch_index: 2,
            segment_offset: 0,
            source_log_size: 8,
            retained_log_size: 9,
            canonical_columns: vec![2, 3],
        },
        BaseCommitOperationKind::DirectB2n {
            batch_index: 1,
            segment_offset: 0,
            source_log_size: 8,
            retained_log_size: 9,
            canonical_columns: vec![3, 2],
        },
        BaseCommitOperationKind::DirectN2b {
            batch_index: 1,
            segment_offset: 0,
            source_log_size: 8,
            retained_log_size: 9,
            canonical_columns: vec![2, 3],
        },
    ];
    assert_eq!(
        operations
            .iter()
            .map(operation_digest)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        operations.len()
    );

    let roles = [
        BaseCommitValueRole::SourceEvaluation {
            canonical_column: 7,
        },
        BaseCommitValueRole::RetainedStageTwo {
            canonical_column: 7,
        },
        BaseCommitValueRole::RetainedEvaluation {
            canonical_column: 7,
        },
        BaseCommitValueRole::State {
            version: 7,
            log_size: 9,
        },
        BaseCommitValueRole::HashLayer { log_size: 9 },
    ];
    assert_eq!(
        roles
            .into_iter()
            .map(role_digest)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        roles.len()
    );
    assert_ne!(
        role_digest(BaseCommitValueRole::State {
            version: 7,
            log_size: 9,
        }),
        role_digest(BaseCommitValueRole::State {
            version: 8,
            log_size: 9,
        })
    );
}

#[test]
fn wrapper_abis_bind_exact_typed_definitions() {
    for abi in BaseCommitAbi::ALL {
        assert!(
            abi.source_declares_entry(abi.wrapper_source()),
            "{}",
            abi.wrapper_symbol()
        );
        assert!(abi
            .arguments()
            .iter()
            .enumerate()
            .all(|(ordinal, argument)| argument.ordinal as usize == ordinal));
        let source = core::str::from_utf8(abi.wrapper_source()).unwrap();
        let renamed = source.replace(abi.wrapper_symbol(), "wrong_base_commit_entry");
        assert!(!abi.source_declares_entry(renamed.as_bytes()));
    }

    assert_eq!(
        BaseCommitAbi::DirectB2nV1
            .arguments()
            .iter()
            .map(|argument| (argument.name, argument.kind, argument.access))
            .collect::<Vec<_>>(),
        vec![
            (
                "inputs",
                BaseCommitAbiArgumentKind::DeviceConstPointerTableU32,
                BaseCommitAbiAccess::ReadSourceEvaluations,
            ),
            (
                "retained_outputs",
                BaseCommitAbiArgumentKind::DeviceMutPointerTableConstU32,
                BaseCommitAbiAccess::WriteRetainedStageTwo,
            ),
            (
                "log_n",
                BaseCommitAbiArgumentKind::U32,
                BaseCommitAbiAccess::TransformLogSize,
            ),
            (
                "num_poly",
                BaseCommitAbiArgumentKind::U32,
                BaseCommitAbiAccess::ColumnCount,
            ),
            (
                "g_twiddles",
                BaseCommitAbiArgumentKind::DeviceConstPointerU32,
                BaseCommitAbiAccess::ReadTwiddles,
            ),
            (
                "twiddles_size",
                BaseCommitAbiArgumentKind::U32,
                BaseCommitAbiAccess::TwiddleWords,
            ),
            (
                "eval_domain_size",
                BaseCommitAbiArgumentKind::U32,
                BaseCommitAbiAccess::EvaluationDomainSize,
            ),
            (
                "stream_raw",
                BaseCommitAbiArgumentKind::CudaStream,
                BaseCommitAbiAccess::OrderedExecutionStream,
            ),
        ]
    );
}

#[test]
fn wrapper_abi_rejects_comment_literal_prototype_and_type_decoys() {
    let abi = BaseCommitAbi::DirectB2nV1;
    let source = core::str::from_utf8(abi.wrapper_source()).unwrap();
    let start = source
        .find("extern \"C\" int stwo_ntt_b2n_columns_to_retained_on")
        .unwrap();
    let end = start + source[start..].find('{').unwrap();
    let header = &source[start..end];
    let drifted = format!(
        "{}{}",
        &source[..start],
        source[start..].replacen(
            "const uint32_t *const *inputs",
            "uint32_t *const *inputs",
            1,
        )
    );
    assert!(!abi.source_declares_entry(drifted.as_bytes()));
    assert!(!abi.source_declares_entry(format!("/* {header} */\n{drifted}").as_bytes()));

    let escaped = header
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    assert!(!abi.source_declares_entry(
        format!("const char *decoy = \"{escaped}\";\n{drifted}").as_bytes()
    ));
    assert!(!abi.source_declares_entry(format!("{header};\n{drifted}").as_bytes()));
    assert!(!abi.source_declares_entry(format!("{header};").as_bytes()));
    assert!(!abi.source_declares_entry(format!("{source}\n{header} {{ return 0; }}").as_bytes()));

    let flat_header = header.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(!abi.source_declares_entry(
        format!("#define DECOY_ENTRY {flat_header} {{ return 0; }}\n").as_bytes()
    ));
    assert!(!abi.source_declares_entry(
        format!("#if 0\nnamespace decoy {{\n{header} {{ return 0; }}\n}}\n#endif\n").as_bytes()
    ));
    assert!(!abi.source_declares_entry(
        format!("#if 0\nnamespace decoy {{\n{header} {{ return 0; }}\n}}\n#endif\n{drifted}")
            .as_bytes()
    ));
}

#[test]
fn effects_cover_every_pointer_alias_scratch_and_stay_monolithic() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();

    for operation in authority.operations() {
        assert_eq!(
            operation.partition,
            BaseCommitPartitionAuthority::Monolithic
        );
        operation.effect.validate_for_abi(operation.abi).unwrap();
        operation
            .invocation
            .validate(operation.abi, &operation.kind, &operation.effect)
            .unwrap();
        assert_eq!(
            operation
                .abi
                .arguments()
                .iter()
                .filter(|argument| argument.kind.is_pointer_bearing())
                .map(|argument| argument.ordinal)
                .collect::<Vec<_>>(),
            operation
                .effect
                .pointer_bindings
                .iter()
                .map(|binding| binding.argument_ordinal)
                .collect::<Vec<_>>()
        );

        let (expected_aliases, expected_scratch_words) = match &operation.kind {
            BaseCommitOperationKind::DirectB2n {
                canonical_columns, ..
            }
            | BaseCommitOperationKind::DirectN2b {
                canonical_columns, ..
            } => (canonical_columns.len(), None),
            BaseCommitOperationKind::StateExpandInPlace { .. } => (1, Some(2 * STATE_WORDS)),
            BaseCommitOperationKind::StateAbsorb { .. } => (1, None),
            BaseCommitOperationKind::StateFinalizeInPlace { .. } => (1, Some(STATE_WORDS)),
            BaseCommitOperationKind::MerkleLayerInPlace { .. } => (1, Some(2 * HASH_WORDS)),
            BaseCommitOperationKind::StateInit { .. }
            | BaseCommitOperationKind::MerkleLayer { .. } => (0, None),
        };
        assert_eq!(operation.effect.aliases.len(), expected_aliases);
        let scratch_words = operation
            .effect
            .pointer_bindings
            .iter()
            .find_map(|binding| {
                let BaseCommitPointerTarget::Installed { access } = &binding.target else {
                    return None;
                };
                if access.role != BaseCommitDependencyRole::InPlaceScratch {
                    return None;
                }
                match access.range {
                    BaseCommitDependencyRange::Whole { words } => Some(words),
                    BaseCommitDependencyRange::Suffix { .. }
                    | BaseCommitDependencyRange::Slice { .. } => None,
                }
            });
        assert_eq!(scratch_words, expected_scratch_words);

        assert_ne!(operation.source_identity, [0; 32]);
        assert_ne!(operation.abi_identity, [0; 32]);
        assert_ne!(operation.effect.identity, [0; 32]);
        assert_ne!(operation.invocation.identity, [0; 32]);
        assert_ne!(operation.launch_identity, [0; 32]);
        assert_ne!(operation.identity, [0; 32]);
    }
}

#[test]
fn pointer_tables_bind_physical_slots_to_ordered_logical_effects() {
    let pointer_words = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();
    let canonical = [2, 5];
    let mut n2b = direct_n2b_effect(7, 0, &canonical, 9).unwrap();
    n2b.validate_for_abi(BaseCommitAbi::DirectN2bV1).unwrap();
    let n2b_table = n2b
        .pointer_bindings
        .iter()
        .find(|binding| binding.argument_ordinal == 0)
        .unwrap();
    let BaseCommitPointerTarget::PointerTable {
        table,
        access_indices,
    } = &n2b_table.target
    else {
        panic!("N2B must bind one retained pointer table");
    };
    assert_eq!(access_indices.len(), 2 * canonical.len());
    assert_eq!(
        table.range,
        BaseCommitDependencyRange::Slice {
            first_word: 0,
            words: canonical.len() * pointer_words,
        }
    );
    for (pair, &canonical_column) in access_indices.chunks_exact(2).zip(&canonical) {
        assert_eq!(
            (
                n2b.accesses[pair[0] as usize].kind,
                n2b.accesses[pair[0] as usize].role,
                n2b.accesses[pair[1] as usize].kind,
                n2b.accesses[pair[1] as usize].role,
            ),
            (
                BaseCommitAccessKind::Read,
                BaseCommitValueRole::RetainedStageTwo { canonical_column },
                BaseCommitAccessKind::Write,
                BaseCommitValueRole::RetainedEvaluation { canonical_column },
            )
        );
    }
    let BaseCommitPointerTarget::PointerTable { access_indices, .. } =
        &mut n2b.pointer_bindings[0].target
    else {
        unreachable!();
    };
    access_indices.swap(1, 2);
    assert_eq!(
        n2b.validate_for_abi(BaseCommitAbi::DirectN2bV1),
        Err(BaseCommitAuthorityError::InvalidEffect)
    );

    let source = BaseCommitValueRole::State {
        version: 1,
        log_size: 9,
    };
    let destination = BaseCommitValueRole::State {
        version: 2,
        log_size: 9,
    };
    let mut absorb = state_absorb_effect(7, 0, 9, source, destination, &canonical).unwrap();
    absorb
        .validate_for_abi(BaseCommitAbi::StateAbsorbV1)
        .unwrap();
    let table_binding = absorb
        .pointer_bindings
        .iter()
        .find(|binding| binding.argument_ordinal == 3)
        .unwrap();
    let state_binding = absorb
        .pointer_bindings
        .iter()
        .find(|binding| binding.argument_ordinal == 4)
        .unwrap();
    assert!(matches!(
        &table_binding.target,
        BaseCommitPointerTarget::PointerTable { .. }
    ));
    assert!(matches!(
        &state_binding.target,
        BaseCommitPointerTarget::Values { .. }
    ));
    absorb.accesses[1].kind = BaseCommitAccessKind::Write;
    assert_eq!(
        absorb.validate_for_abi(BaseCommitAbi::StateAbsorbV1),
        Err(BaseCommitAuthorityError::InvalidEffect)
    );
}

#[test]
fn invocation_and_effect_mutations_fail_revalidation() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();

    let mut changed = authority.clone();
    changed.operations[0].invocation.arguments[0].value = BaseCommitInvocationValue::U32(0);
    assert_eq!(
        changed.validate(),
        Err(BaseCommitAuthorityError::ProgramMismatch)
    );

    let mut changed = authority;
    changed.operations[0].effect.pointer_bindings.pop();
    assert_eq!(
        changed.operations[0]
            .effect
            .validate_for_abi(changed.operations[0].abi),
        Err(BaseCommitAuthorityError::InvalidEffect)
    );
    assert_eq!(
        changed.validate(),
        Err(BaseCommitAuthorityError::ProgramMismatch)
    );
}

#[test]
fn every_transitive_source_component_changes_the_source_identity() {
    let static_source = stwo_backend_cuda_kernels::static_cuda_source_identity();
    let sources = authority_sources();
    let baseline = source_identity_from_parts(static_source, 7, 11, &sources).unwrap();
    for index in 0..sources.len() {
        let mut changed = sources.to_vec();
        changed[index] = b"mutated-source-component";
        assert_ne!(
            source_identity_from_parts(static_source, 7, 11, &changed).unwrap(),
            baseline,
            "source index {index}"
        );
    }
}

#[test]
fn compiler_accepts_lowerable_fusion_and_rejects_wrong_role_interior_and_pair() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let interaction =
        DirectRetainedB2nProgram::compile(TraceTreeRole::Interaction, &commit).unwrap();
    assert_eq!(
        BaseCommitProgramAuthority::compile(&commit, &interaction),
        Err(BaseCommitAuthorityError::UnsupportedRole(
            TraceTreeRole::Interaction
        ))
    );

    let (fused, fused_direct) = programs(ProgressiveNttLeafFusionMode::Fused16, false, 0);
    BaseCommitProgramAuthority::compile(&fused, &fused_direct)
        .unwrap()
        .validate()
        .unwrap();

    let (interior, interior_direct) = programs(ProgressiveNttLeafFusionMode::Separate, true, 0);
    assert_eq!(
        BaseCommitProgramAuthority::compile(&interior, &interior_direct),
        Err(BaseCommitAuthorityError::UnsupportedInteriorFusion)
    );

    let (tail, tail_direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 1);
    let tail_authority = BaseCommitProgramAuthority::compile(&tail, &tail_direct).unwrap();
    tail_authority.validate().unwrap();
    assert_eq!(
        tail_authority.commit_operation_view().unwrap(),
        tail.steps()
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>()
    );

    let other = CommitProgram::compile(
        commit.identity().config,
        ProgressiveCommitGeometry {
            lifting_log_size: 6,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![3, 3, 5],
                retain_evaluations: true,
            }],
        },
        ProgressiveNttLeafFusionMode::Separate,
        false,
    )
    .unwrap();
    assert_eq!(
        BaseCommitProgramAuthority::compile(&other, &direct),
        Err(BaseCommitAuthorityError::ProgramMismatch)
    );
}

#[test]
fn linked_authority_revalidates_only_the_exact_program_and_build() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    if stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT {
        let target = stwo_backend_cuda_kernels::static_cuda_module_target_sms()[0];
        let linked = authority.bind_static_build(target).unwrap().unwrap();
        linked.validate(&authority).unwrap();

        let mut changed = linked;
        changed.program_identity[0] ^= 1;
        assert_eq!(
            changed.validate(&authority),
            Err(BaseCommitAuthorityError::StaticBuildMismatch)
        );
    } else {
        assert_eq!(authority.bind_static_build(89).unwrap(), None);
    }

    let mut changed = authority;
    changed.identity[0] ^= 1;
    assert_eq!(
        changed.validate(),
        Err(BaseCommitAuthorityError::ProgramMismatch)
    );
}
