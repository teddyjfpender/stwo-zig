use super::super::effect::direct_b2n_effect;
use super::super::encoding::{
    launch_identity, linked_authority, operation_identity, program_identity,
};
use super::super::execution::execution_manifest;
use super::*;
use crate::backend::prepared_witness_input::static_build::StaticBuildBinding;

fn programs_for_logs(
    coefficient_log_sizes: Vec<u32>,
    lifting_log_size: u32,
    fusion: ProgressiveNttLeafFusionMode,
    tail_levels: u32,
) -> (CommitProgram, DirectRetainedB2nProgram) {
    let commit = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size,
            unretained_bottom_layers: 4.min(lifting_log_size),
            max_fused_tail_levels: tail_levels,
        },
        ProgressiveCommitGeometry {
            lifting_log_size,
            log_blowup_factor: 1,
            groups: vec![ProgressiveCommitGroupGeometry {
                coefficient_log_sizes,
                retain_evaluations: true,
            }],
        },
        fusion,
        false,
    )
    .unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &commit).unwrap();
    (commit, direct)
}

fn pointer_table_range(
    operation: &BaseCommitOperation,
    argument_ordinal: u8,
) -> BaseCommitDependencyRange {
    operation
        .effect
        .pointer_bindings
        .iter()
        .find_map(|binding| {
            if binding.argument_ordinal != argument_ordinal {
                return None;
            }
            let BaseCommitPointerTarget::PointerTable { table, .. } = binding.target else {
                return None;
            };
            Some(table.range)
        })
        .unwrap()
}

#[test]
fn fused_leaf_and_tail_lower_to_exact_ordinary_wrapper_order() {
    let (commit, direct) =
        programs_for_logs(vec![12; 17], 13, ProgressiveNttLeafFusionMode::Fused16, 2);
    assert!(commit.steps().iter().any(|step| matches!(
        step.operation,
        CommitProgramOperation::FusedLdeAbsorb16 { .. }
    )));
    assert!(matches!(
        commit.steps().last().unwrap().operation,
        CommitProgramOperation::MerkleTail {
            first_hashes: 4,
            levels: 2
        }
    ));

    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    authority.validate().unwrap();
    assert_eq!(
        authority.commit_operation_view().unwrap(),
        commit
            .steps()
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>()
    );

    let fused = authority
        .operations()
        .windows(3)
        .find(|operations| {
            matches!(
                &operations[0].kind,
                BaseCommitOperationKind::DirectB2n {
                    segment_offset: 0,
                    canonical_columns,
                    ..
                } if canonical_columns.len() == 16
            )
        })
        .unwrap();
    assert!(matches!(
        fused[1].kind,
        BaseCommitOperationKind::DirectN2b {
            segment_offset: 0,
            ..
        }
    ));
    assert!(matches!(
        fused[2].kind,
        BaseCommitOperationKind::StateAbsorb {
            segment_offset: 0,
            ..
        }
    ));
    let later = authority
        .operations()
        .windows(3)
        .find(|operations| {
            matches!(
                operations,
                [
                    BaseCommitOperation {
                        kind: BaseCommitOperationKind::DirectB2n {
                            segment_offset: 16,
                            ..
                        },
                        ..
                    },
                    BaseCommitOperation {
                        kind: BaseCommitOperationKind::DirectN2b {
                            segment_offset: 16,
                            ..
                        },
                        ..
                    },
                    BaseCommitOperation {
                        kind: BaseCommitOperationKind::StateAbsorb {
                            segment_offset: 16,
                            ..
                        },
                        ..
                    }
                ]
            )
        })
        .unwrap();
    let pointer_words = core::mem::size_of::<usize>() / core::mem::size_of::<u32>();
    for (operation, ordinal) in [
        (&fused[0], 0),
        (&fused[0], 1),
        (&fused[1], 0),
        (&fused[2], 3),
    ] {
        assert_eq!(
            pointer_table_range(operation, ordinal),
            BaseCommitDependencyRange::Slice {
                first_word: 0,
                words: 16 * pointer_words,
            }
        );
    }
    for (operation, ordinal) in [
        (&later[0], 0),
        (&later[0], 1),
        (&later[1], 0),
        (&later[2], 3),
    ] {
        assert_eq!(
            pointer_table_range(operation, ordinal),
            BaseCommitDependencyRange::Slice {
                first_word: 16 * pointer_words,
                words: pointer_words,
            }
        );
    }
    assert_ne!(fused[0].invocation.identity, later[0].invocation.identity);
    let BaseCommitOperationKind::DirectB2n {
        batch_index,
        source_log_size,
        retained_log_size,
        canonical_columns,
        ..
    } = &later[0].kind
    else {
        unreachable!()
    };
    let wrong_offset_effect = direct_b2n_effect(
        *batch_index,
        0,
        canonical_columns,
        *source_log_size,
        *retained_log_size,
    )
    .unwrap();
    assert_eq!(
        later[0]
            .invocation
            .validate(later[0].abi, &later[0].kind, &wrong_offset_effect),
        Err(BaseCommitAuthorityError::InvalidInvocation)
    );
    assert!(matches!(
        authority.operations()[authority.operations().len() - 2..],
        [
            BaseCommitOperation {
                kind: BaseCommitOperationKind::MerkleLayer {
                    level: 11,
                    output_hashes: 2
                },
                ..
            },
            BaseCommitOperation {
                kind: BaseCommitOperationKind::MerkleLayer {
                    level: 12,
                    output_hashes: 1
                },
                ..
            }
        ]
    ));
}

#[test]
fn execution_manifest_seals_exact_kernel_geometry_copy_bytes_and_order() {
    let b2n = execution_manifest(&BaseCommitOperationKind::DirectB2n {
        batch_index: 17,
        segment_offset: 32,
        source_log_size: 24,
        retained_log_size: 25,
        canonical_columns: (0..54).collect(),
    })
    .unwrap();
    assert_eq!(
        b2n.iter()
            .map(|step| match step {
                BaseCommitExecutionStep::KernelLaunch(launch) => {
                    (launch.symbol, launch.grid, launch.block)
                }
                BaseCommitExecutionStep::DeviceCopyD2D { .. } => unreachable!(),
            })
            .collect::<Vec<_>>(),
        vec![
            ("b2n_init_warp_batch<3>", [16_384, 54, 1], [32, 4, 1]),
            ("b2n_noinit_block_batch<4,false>", [8, 256, 54], [32, 16, 1]),
            (
                "b2n_noinit_block_batch<4,true>",
                [2_048, 1, 54],
                [32, 16, 1]
            ),
        ]
    );
    let BaseCommitExecutionStep::KernelLaunch(first_b2n) = &b2n[0] else {
        unreachable!()
    };
    assert_eq!(
        first_b2n.arguments,
        vec![
            BaseCommitKernelArgument {
                name: "input",
                value: BaseCommitKernelArgumentValue::Buffer(
                    BaseCommitExecutionBuffer::WrapperArgument {
                        ordinal: 0,
                        byte_offset: 0,
                    }
                ),
            },
            BaseCommitKernelArgument {
                name: "output",
                value: BaseCommitKernelArgumentValue::Buffer(
                    BaseCommitExecutionBuffer::WrapperArgument {
                        ordinal: 1,
                        byte_offset: 0,
                    }
                ),
            },
            BaseCommitKernelArgument {
                name: "log_n",
                value: BaseCommitKernelArgumentValue::U32(24),
            },
            BaseCommitKernelArgument {
                name: "num_poly",
                value: BaseCommitKernelArgumentValue::U32(54),
            },
            BaseCommitKernelArgument {
                name: "min_stage",
                value: BaseCommitKernelArgumentValue::U32(1),
            },
            BaseCommitKernelArgument {
                name: "max_stage",
                value: BaseCommitKernelArgumentValue::U32(8),
            },
            BaseCommitKernelArgument {
                name: "g_twiddles",
                value: BaseCommitKernelArgumentValue::Buffer(
                    BaseCommitExecutionBuffer::DependencySuffix {
                        role: BaseCommitDependencyRole::InverseTwiddles,
                        byte_offset: 0,
                    }
                ),
            },
        ]
    );

    let n2b = execution_manifest(&BaseCommitOperationKind::DirectN2b {
        batch_index: 17,
        segment_offset: 32,
        source_log_size: 24,
        retained_log_size: 25,
        canonical_columns: (0..54).collect(),
    })
    .unwrap();
    assert_eq!(
        n2b.iter()
            .map(|step| match step {
                BaseCommitExecutionStep::KernelLaunch(launch) => {
                    (launch.symbol, launch.grid, launch.block)
                }
                BaseCommitExecutionStep::DeviceCopyD2D { .. } => unreachable!(),
            })
            .collect::<Vec<_>>(),
        vec![
            ("n2b_nofinal_block_batch<3,2>", [16_384, 2, 54], [32, 4, 1]),
            ("n2b_nofinal_block_batch<4,4>", [64, 64, 54], [32, 16, 1]),
            (
                "n2b_final_block_warp_batch<3,true>",
                [16_384, 1, 54],
                [32, 8, 1]
            ),
        ]
    );

    let tiled = execution_manifest(&BaseCommitOperationKind::DirectB2n {
        batch_index: 18,
        segment_offset: 0,
        source_log_size: 13,
        retained_log_size: 14,
        canonical_columns: (0..65_536).collect(),
    })
    .unwrap();
    assert_eq!(tiled.len(), 4);
    assert_eq!(
        tiled
            .iter()
            .filter_map(|step| match step {
                BaseCommitExecutionStep::KernelLaunch(launch) => Some(launch.grid),
                BaseCommitExecutionStep::DeviceCopyD2D { .. } => None,
            })
            .collect::<Vec<_>>(),
        [[16, 65_535, 1], [4, 1, 65_535], [16, 1, 1], [4, 1, 1]]
    );
    let BaseCommitExecutionStep::KernelLaunch(second_chunk) = &tiled[2] else {
        unreachable!()
    };
    assert!(second_chunk.arguments.iter().any(|argument| {
        matches!(
            argument,
            BaseCommitKernelArgument {
                name: "input",
                value: BaseCommitKernelArgumentValue::Buffer(
                    BaseCommitExecutionBuffer::WrapperArgument {
                        ordinal: 0,
                        byte_offset,
                    }
                ),
            } if *byte_offset == 65_535 * core::mem::size_of::<usize>() as u64
        )
    }));

    let tiled_n2b = execution_manifest(&BaseCommitOperationKind::DirectN2b {
        batch_index: 18,
        segment_offset: 0,
        source_log_size: 12,
        retained_log_size: 13,
        canonical_columns: (0..65_536).collect(),
    })
    .unwrap();
    assert_eq!(
        tiled_n2b
            .iter()
            .map(|step| match step {
                BaseCommitExecutionStep::KernelLaunch(launch) => launch.grid,
                BaseCommitExecutionStep::DeviceCopyD2D { .. } => unreachable!(),
            })
            .collect::<Vec<_>>(),
        [[4, 2, 65_535], [16, 65_535, 1], [4, 2, 1], [16, 1, 1]]
    );
    let BaseCommitExecutionStep::KernelLaunch(second_n2b_chunk) = &tiled_n2b[2] else {
        unreachable!()
    };
    assert!(second_n2b_chunk.arguments.iter().any(|argument| {
        matches!(
            argument,
            BaseCommitKernelArgument {
                name: "input",
                value: BaseCommitKernelArgumentValue::Buffer(
                    BaseCommitExecutionBuffer::WrapperArgument {
                        ordinal: 0,
                        byte_offset,
                    }
                ),
            } if *byte_offset == 65_535 * core::mem::size_of::<usize>() as u64
        )
    }));

    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    for operation in authority.operations() {
        let copies = operation
            .execution
            .iter()
            .enumerate()
            .filter_map(|(index, step)| match step {
                BaseCommitExecutionStep::DeviceCopyD2D {
                    source,
                    destination,
                    bytes,
                } => Some((index, *source, *destination, *bytes)),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected = match operation.kind {
            BaseCommitOperationKind::StateExpandInPlace { .. } => vec![(
                0,
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 2,
                    byte_offset: 0,
                },
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 3,
                    byte_offset: 0,
                },
                2 * PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64,
            )],
            BaseCommitOperationKind::StateFinalizeInPlace { .. } => vec![(
                0,
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 2,
                    byte_offset: 0,
                },
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 3,
                    byte_offset: 0,
                },
                PROGRESSIVE_BLAKE2S_STATE_STRIDE_BYTES as u64,
            )],
            BaseCommitOperationKind::MerkleLayerInPlace { .. } => vec![(
                0,
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 1,
                    byte_offset: 0,
                },
                BaseCommitExecutionBuffer::WrapperArgument {
                    ordinal: 2,
                    byte_offset: 0,
                },
                (2 * core::mem::size_of::<Blake2sHash>()) as u64,
            )],
            _ => vec![],
        };
        assert_eq!(copies, expected, "{:?}", operation.kind);
    }
}

#[test]
fn execution_mutations_change_operation_program_and_linked_identities() {
    let (commit, direct) = programs(ProgressiveNttLeafFusionMode::Separate, false, 0);
    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    let index = authority
        .operations()
        .iter()
        .position(|operation| {
            matches!(
                operation.kind,
                BaseCommitOperationKind::StateExpandInPlace { .. }
            )
        })
        .unwrap();
    let operation = &authority.operations()[index];
    let baseline = operation.launch_identity;

    let mut copy_bytes = operation.execution.clone();
    let BaseCommitExecutionStep::DeviceCopyD2D { bytes, .. } = &mut copy_bytes[0] else {
        unreachable!()
    };
    *bytes += 4;

    let mut copy_endpoint = operation.execution.clone();
    let BaseCommitExecutionStep::DeviceCopyD2D { source, .. } = &mut copy_endpoint[0] else {
        unreachable!()
    };
    *source = BaseCommitExecutionBuffer::WrapperArgument {
        ordinal: 1,
        byte_offset: 0,
    };

    let mut reordered = operation.execution.clone();
    reordered.swap(0, 1);

    let mut geometry = operation.execution.clone();
    let BaseCommitExecutionStep::KernelLaunch(launch) = &mut geometry[1] else {
        unreachable!()
    };
    launch.grid[0] += 1;

    let mut symbol = operation.execution.clone();
    let BaseCommitExecutionStep::KernelLaunch(launch) = &mut symbol[1] else {
        unreachable!()
    };
    launch.symbol = "wrong_kernel";

    for changed in [&copy_bytes, &copy_endpoint, &reordered, &geometry, &symbol] {
        assert_ne!(
            launch_identity(operation.abi, &operation.kind, changed).unwrap(),
            baseline
        );
        let mut mutated = authority.clone();
        mutated.operations[index].execution = changed.clone();
        assert_eq!(
            mutated.validate(),
            Err(BaseCommitAuthorityError::ProgramMismatch)
        );
    }

    let mut operations = authority.operations().to_vec();
    let changed_launch = launch_identity(operation.abi, &operation.kind, &copy_bytes).unwrap();
    operations[index].launch_identity = changed_launch;
    operations[index].identity = operation_identity(
        operation.source_identity,
        operation.abi_identity,
        operation.effect.identity,
        operation.invocation.identity,
        changed_launch,
        &operation.partition,
    )
    .unwrap();
    let changed_program = program_identity(
        authority.commit(),
        authority.direct(),
        authority.source_identity(),
        authority.layouts(),
        &operations,
        authority.retained_evaluations(),
        authority.retained_layers_bottom_up(),
        authority.root(),
    )
    .unwrap();
    assert_ne!(changed_program, authority.identity());

    let binding = StaticBuildBinding {
        module_build_identity: [1; 32],
        static_build_source_identity: [2; 32],
        target_sm: 89,
        sm_identity: [3; 32],
        identity: [4; 32],
    };
    assert_ne!(
        linked_authority(authority.identity(), binding).identity(),
        linked_authority(changed_program, binding).identity()
    );

    let stage_index = authority
        .operations()
        .iter()
        .position(|operation| matches!(operation.kind, BaseCommitOperationKind::DirectB2n { .. }))
        .unwrap();
    let stage_operation = &authority.operations()[stage_index];
    let mut changed_stage = stage_operation.execution.clone();
    let argument = changed_stage
        .iter_mut()
        .find_map(|step| {
            let BaseCommitExecutionStep::KernelLaunch(launch) = step else {
                return None;
            };
            launch
                .arguments
                .iter_mut()
                .find(|argument| argument.name == "stage")
        })
        .unwrap();
    let BaseCommitKernelArgumentValue::U32(stage) = &mut argument.value else {
        unreachable!()
    };
    *stage += 1;
    assert_ne!(
        launch_identity(stage_operation.abi, &stage_operation.kind, &changed_stage).unwrap(),
        stage_operation.launch_identity
    );
    let mut mutated = authority.clone();
    mutated.operations[stage_index].execution = changed_stage;
    assert_eq!(
        mutated.validate(),
        Err(BaseCommitAuthorityError::ProgramMismatch)
    );
}

#[test]
fn generated_live_sn2_base_histogram_admits_fused16_and_tail12() {
    const HISTOGRAM: [(u32, usize); 18] = [
        (4, 1),
        (6, 2),
        (7, 1),
        (8, 92),
        (9, 46),
        (10, 289),
        (11, 1),
        (12, 343),
        (13, 6),
        (14, 2),
        (15, 336),
        (16, 194),
        (17, 308),
        (18, 705),
        (19, 275),
        (20, 727),
        (21, 67),
        (23, 54),
    ];
    let logs = HISTOGRAM
        .into_iter()
        .flat_map(|(log_size, columns)| std::iter::repeat_n(log_size, columns))
        .collect::<Vec<_>>();
    assert_eq!(logs.len(), 3_449);
    let (commit, direct) = programs_for_logs(logs, 24, ProgressiveNttLeafFusionMode::Fused16, 12);
    assert_eq!(direct.batches().len(), 18);
    assert!(commit.steps().iter().any(|step| matches!(
        step.operation,
        CommitProgramOperation::FusedLdeAbsorb16 { .. }
    )));
    assert!(matches!(
        commit.steps().last().unwrap().operation,
        CommitProgramOperation::MerkleTail {
            first_hashes: 4_096,
            levels: 12
        }
    ));

    let authority = BaseCommitProgramAuthority::compile(&commit, &direct).unwrap();
    authority.validate().unwrap();
    assert_eq!(
        authority.commit_operation_view().unwrap(),
        commit
            .steps()
            .iter()
            .map(|step| step.operation)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        authority.root(),
        BaseCommitValueRole::HashLayer { log_size: 0 }
    );
    assert!(authority.operations().iter().all(|operation| {
        !operation.execution.is_empty()
            && operation.execution.iter().all(|step| match step {
                BaseCommitExecutionStep::KernelLaunch(launch) => {
                    !launch.symbol.is_empty()
                        && !launch.grid.contains(&0)
                        && !launch.block.contains(&0)
                }
                BaseCommitExecutionStep::DeviceCopyD2D { bytes, .. } => *bytes != 0,
            })
    }));
}
