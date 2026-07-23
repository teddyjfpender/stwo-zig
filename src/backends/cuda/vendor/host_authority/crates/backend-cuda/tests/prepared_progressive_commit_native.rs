//! Native CUDA differential for the domain-progressive leaf producer.
//!
//! A stub build compiles zero tests. Hardware admission must compare every
//! produced leaf against both the progressive-state oracle and full lifting.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_hash::{Blake2sHash, Blake2sHasherGeneric};
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo_backend_cuda::{
    full_lifting_leaf_oracle, progressive_leaf_oracle,
    progressive_leaf_workspace_requirements_for_mode, ArenaLayout, ArenaSlice, ArenaSlotId,
    ArenaSlotSpec, CommitArenaSlotRequirement, CommitCoefficientColumn, CudaExecContext,
    DeviceArena, PreparedProgressiveLeaves, ProgressiveBatchSlots, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry, ProgressiveCommitMode, ProgressiveLeafLaunchKind,
    ProgressiveLeafWorkspaceRequirements, ProgressiveLeafWorkspaceSlots,
    ProgressiveNttLeafFusionMode,
};

const TWIDDLES: ArenaSlotId = ArenaSlotId(50_000);
const SOURCE_BASE: u32 = 51_000;
const OUTPUT_BASE: u32 = 52_000;

fn workspace_slots(
    requirements: &ProgressiveLeafWorkspaceRequirements,
) -> ProgressiveLeafWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    ProgressiveLeafWorkspaceSlots {
        lde_scratch: requirements.lde_scratch_words.map(|_| id()),
        state_ping: id(),
        state_pong: requirements.state_pong_words.map(|_| id()),
        leaf_hashes: id(),
        batches: requirements
            .batches
            .iter()
            .map(|_| ProgressiveBatchSlots {
                coefficient_ptrs: id(),
                coefficient_sizes: id(),
                output_ptrs: id(),
            })
            .collect(),
    }
}

fn arena(
    requirements: &ProgressiveLeafWorkspaceRequirements,
    slots: &ProgressiveLeafWorkspaceSlots,
) -> DeviceArena {
    let mut requested = requirements.arena_slot_requirements(slots).unwrap();
    requested.push(CommitArenaSlotRequirement {
        id: TWIDDLES,
        len_words: requirements.twiddle_words,
        alignment_words: 1,
    });
    for column in &requirements.plan.columns {
        requested.push(CommitArenaSlotRequirement {
            id: ArenaSlotId(SOURCE_BASE + column.canonical_index as u32),
            len_words: 1usize << column.coefficient_log_size,
            alignment_words: 1,
        });
        if column.retained_evaluation {
            requested.push(CommitArenaSlotRequirement {
                id: ArenaSlotId(OUTPUT_BASE + column.canonical_index as u32),
                len_words: 1usize << column.evaluation_log_size,
                alignment_words: 1,
            });
        }
    }
    let mut offset = 0usize;
    let specs = requested
        .into_iter()
        .map(|requirement| {
            offset = offset.next_multiple_of(requirement.alignment_words);
            let spec = ArenaSlotSpec {
                id: requirement.id,
                offset_words: offset,
                len_words: requirement.len_words,
                alignment_words: requirement.alignment_words,
            };
            offset += requirement.len_words;
            spec
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset, &specs).unwrap(),
    )
    .unwrap()
}

fn upload(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    let destination = arena.bind(slot).unwrap();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                words.as_ptr().cast(),
                core::mem::size_of_val(words),
            )
            .unwrap();
    }
}

fn read_hashes(arena: &DeviceArena, source: ArenaSlice) -> Vec<Blake2sHash> {
    let mut result = vec![Blake2sHash::default(); source.len_words() / 8];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(result.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

fn read_words(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut result = vec![0u32; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                result.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(result.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    result
}

fn evaluate(log_size: u32, blowup: u32, coefficients: &[u32]) -> Vec<u32> {
    let domain = CanonicCoset::new(log_size + blowup).circle_domain();
    let twiddles = CpuBackend::precompute_twiddles(domain.half_coset);
    CircleCoefficients::<CpuBackend>::new(
        coefficients
            .iter()
            .copied()
            .map(BaseField::from_u32_unchecked)
            .collect(),
    )
    .evaluate_with_twiddles(domain, &twiddles)
    .values
    .into_iter()
    .map(|value| value.0)
    .collect()
}

fn coefficient_set(
    requirements: &ProgressiveLeafWorkspaceRequirements,
    seed: u64,
) -> Vec<Vec<u32>> {
    requirements
        .plan
        .columns
        .iter()
        .map(|column| {
            (0..1usize << column.coefficient_log_size)
                .map(|row| {
                    (seed + (column.canonical_index as u64 + 1) * 104_729 + row as u64 * 7_919)
                        .rem_euclid(0x7fff_ffff) as u32
                })
                .collect()
        })
        .collect()
}

fn expected_evaluations(
    requirements: &ProgressiveLeafWorkspaceRequirements,
    coefficient_words: &[Vec<u32>],
) -> Vec<Vec<u32>> {
    requirements
        .plan
        .columns
        .iter()
        .zip(coefficient_words)
        .map(|(column, words)| {
            evaluate(
                column.coefficient_log_size,
                requirements.plan.geometry.log_blowup_factor,
                words,
            )
        })
        .collect()
}

fn assert_outputs(
    arena: &DeviceArena,
    prepared: &PreparedProgressiveLeaves<'_>,
    requirements: &ProgressiveLeafWorkspaceRequirements,
    retained: &[Option<ArenaSlice>],
    evaluations: &[Vec<u32>],
) -> Vec<Blake2sHash> {
    let actual = read_hashes(arena, prepared.leaf_hashes());
    assert_eq!(
        actual,
        progressive_leaf_oracle(&requirements.plan, evaluations).unwrap()
    );
    assert_eq!(
        actual,
        full_lifting_leaf_oracle(&requirements.plan, evaluations).unwrap()
    );
    for (column, (destination, expected)) in retained.iter().zip(evaluations).enumerate() {
        if let Some(destination) = destination {
            assert_eq!(
                read_words(arena, *destination),
                *expected,
                "retained LDE column {column} changed or was not refreshed"
            );
        }
    }
    actual
}

fn run_boundary_case(
    total_columns: usize,
    rise_after: Option<usize>,
    retained_columns: &[bool],
    expected_batch_columns: &[usize],
    expected_scratch_words: usize,
) {
    assert!(total_columns >= 2);
    assert_eq!(retained_columns.len(), total_columns);
    if let Some(rise_after) = rise_after {
        assert!(rise_after < total_columns);
    }
    let logs = (0..total_columns)
        .map(|column| {
            if rise_after.is_some_and(|rise| column >= rise) {
                4
            } else {
                3
            }
        })
        .collect::<Vec<_>>();
    let mut groups = Vec::new();
    let mut group_start = 0usize;
    while group_start < total_columns {
        let retained = retained_columns[group_start];
        let mut group_end = group_start + 1;
        while group_end < total_columns && retained_columns[group_end] == retained {
            group_end += 1;
        }
        groups.push(ProgressiveCommitGroupGeometry {
            coefficient_log_sizes: logs[group_start..group_end].to_vec(),
            retain_evaluations: retained,
        });
        group_start = group_end;
    }
    let geometry = ProgressiveCommitGeometry {
        lifting_log_size: 6,
        log_blowup_factor: 1,
        // Same-log batches may cross retention-group edges while preserving
        // canonical column order.
        groups,
    };
    let requirements = progressive_leaf_workspace_requirements_for_mode(
        ProgressiveCommitMode::DomainProgressive,
        geometry.clone(),
    )
    .unwrap();
    let slots = workspace_slots(&requirements);
    let arena = arena(&requirements, &slots);

    let max_evaluation_log = requirements
        .plan
        .columns
        .iter()
        .map(|column| column.evaluation_log_size)
        .max()
        .unwrap();
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(max_evaluation_log)
            .circle_domain()
            .half_coset,
    );
    upload(
        &arena,
        TWIDDLES,
        &twiddles
            .twiddles
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>(),
    );
    let first_coefficients = coefficient_set(&requirements, 4_242);
    let coefficients = requirements
        .plan
        .columns
        .iter()
        .zip(&first_coefficients)
        .map(|(column, words)| {
            let slot = ArenaSlotId(SOURCE_BASE + column.canonical_index as u32);
            upload(&arena, slot, words);
            CommitCoefficientColumn {
                coefficients: arena.bind(slot).unwrap(),
                log_size: column.coefficient_log_size,
            }
        })
        .collect::<Vec<_>>();
    let retained = requirements
        .plan
        .columns
        .iter()
        .map(|column| {
            column.retained_evaluation.then(|| {
                arena
                    .bind(ArenaSlotId(OUTPUT_BASE + column.canonical_index as u32))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    arena.context().sync().unwrap();

    assert!(matches!(
        PreparedProgressiveLeaves::prepare_with_mode(
            &arena,
            &requirements,
            &slots,
            &coefficients,
            &retained,
            arena.bind(TWIDDLES).unwrap(),
            ProgressiveCommitMode::FullLifting,
        ),
        Err(stwo_backend_cuda::PreparedProgressiveCommitError::Disabled)
    ));
    let prepared = PreparedProgressiveLeaves::prepare_with_mode(
        &arena,
        &requirements,
        &slots,
        &coefficients,
        &retained,
        arena.bind(TWIDDLES).unwrap(),
        ProgressiveCommitMode::DomainProgressive,
    )
    .unwrap();
    assert_eq!(requirements.lde_scratch_words, Some(expected_scratch_words));
    assert_eq!(
        requirements
            .plan
            .lde_batches
            .iter()
            .map(|batch| batch.columns.len())
            .collect::<Vec<_>>(),
        expected_batch_columns
    );
    assert_eq!(
        prepared
            .launch_sequence()
            .filter(|launch| matches!(launch, ProgressiveLeafLaunchKind::Lde { .. }))
            .count(),
        expected_batch_columns.len()
    );
    assert!(requirements.plan.lde_batches.iter().all(|batch| {
        batch
            .retained_columns
            .iter()
            .filter(|destination| destination.is_none())
            .count()
            <= 16
    }));

    let first_evaluations = expected_evaluations(&requirements, &first_coefficients);
    prepared.launch().unwrap();
    let eager_leaves = assert_outputs(
        &arena,
        &prepared,
        &requirements,
        &retained,
        &first_evaluations,
    );

    // Capture is deliberately outside prepare and after one eager differential.
    // Replays must reread stable coefficient addresses, not bake input contents
    // into the graph.
    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();

    graph.launch(arena.context()).unwrap();
    let first_leaves = assert_outputs(
        &arena,
        &prepared,
        &requirements,
        &retained,
        &first_evaluations,
    );
    assert_eq!(first_leaves, eager_leaves);

    let second_coefficients = coefficient_set(&requirements, 9_999_991);
    for (column, words) in requirements.plan.columns.iter().zip(&second_coefficients) {
        upload(
            &arena,
            ArenaSlotId(SOURCE_BASE + column.canonical_index as u32),
            words,
        );
    }
    graph.launch(arena.context()).unwrap();
    let second_evaluations = expected_evaluations(&requirements, &second_coefficients);
    let second_leaves = assert_outputs(
        &arena,
        &prepared,
        &requirements,
        &retained,
        &second_evaluations,
    );
    assert_ne!(
        first_leaves, second_leaves,
        "coefficient mutation did not refresh leaves"
    );

    // A second replay after mutation proves retained outputs persist and the
    // graph remains reusable after D2H inspection boundaries.
    graph.launch(arena.context()).unwrap();
    let replayed_leaves = assert_outputs(
        &arena,
        &prepared,
        &requirements,
        &retained,
        &second_evaluations,
    );
    assert_eq!(replayed_leaves, second_leaves);
}

#[test]
fn progressive_lazy_block_boundaries_rises_retention_and_replay_match_cpu() {
    for (columns, rise_after) in [
        (16, None),
        (17, Some(16)),
        (18, Some(17)),
        (32, None),
        (33, Some(32)),
    ] {
        let retained = (0..columns).map(|column| column != 0).collect::<Vec<_>>();
        let expected_batches = match rise_after {
            Some(rise) => vec![rise, columns - rise],
            None => vec![columns],
        };
        run_boundary_case(columns, rise_after, &retained, &expected_batches, 1 << 4);
    }
    // Three consecutive same-log chunks overwrite the one 16-column scratch
    // slab only after each preceding absorb. Eager capture and mutated replay
    // below prove that reuse preserves every leaf byte.
    run_boundary_case(33, None, &[false; 33], &[16, 16, 1], 16 * (1 << 4));

    // Sixteen scratch-backed columns separated by 33 retained destinations
    // coalesce into one canonical batch. The native differential proves the
    // larger absorb loop, mixed pointer table, capture and mutation all retain
    // exact leaf bytes without growing shared scratch.
    let retained = (0..49)
        .map(|column| (8..41).contains(&column))
        .collect::<Vec<_>>();
    run_boundary_case(49, None, &retained, &[49], 16 * (1 << 4));
}

#[test]
fn progressive_final_ntt_fusion_matches_separate_eager_capture_and_retained_outputs() {
    let retained_flags = (0..32)
        .map(|column| (4..24).contains(&column))
        .collect::<Vec<_>>();
    let mut groups = Vec::new();
    for run in retained_flags.chunk_by(|left, right| left == right) {
        groups.push(ProgressiveCommitGroupGeometry {
            coefficient_log_sizes: vec![12; run.len()],
            retain_evaluations: run[0],
        });
    }
    let requirements = progressive_leaf_workspace_requirements_for_mode(
        ProgressiveCommitMode::DomainProgressive,
        ProgressiveCommitGeometry {
            lifting_log_size: 13,
            log_blowup_factor: 1,
            groups,
        },
    )
    .unwrap();
    assert_eq!(requirements.plan.lde_batches.len(), 1);
    let slots = workspace_slots(&requirements);
    let arena = arena(&requirements, &slots);
    let twiddles =
        CpuBackend::precompute_twiddles(CanonicCoset::new(13).circle_domain().half_coset);
    upload(
        &arena,
        TWIDDLES,
        &twiddles
            .twiddles
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>(),
    );
    let first_coefficients = coefficient_set(&requirements, 67_891);
    let coefficients = requirements
        .plan
        .columns
        .iter()
        .zip(&first_coefficients)
        .map(|(column, words)| {
            let slot = ArenaSlotId(SOURCE_BASE + column.canonical_index as u32);
            upload(&arena, slot, words);
            CommitCoefficientColumn {
                coefficients: arena.bind(slot).unwrap(),
                log_size: column.coefficient_log_size,
            }
        })
        .collect::<Vec<_>>();
    let retained = requirements
        .plan
        .columns
        .iter()
        .map(|column| {
            column.retained_evaluation.then(|| {
                arena
                    .bind(ArenaSlotId(OUTPUT_BASE + column.canonical_index as u32))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    arena.context().sync().unwrap();

    let separate = PreparedProgressiveLeaves::prepare_with_mode_and_ntt_fusion(
        &arena,
        &requirements,
        &slots,
        &coefficients,
        &retained,
        arena.bind(TWIDDLES).unwrap(),
        ProgressiveCommitMode::DomainProgressive,
        ProgressiveNttLeafFusionMode::Separate,
    )
    .unwrap();
    let first_evaluations = expected_evaluations(&requirements, &first_coefficients);
    separate.launch().unwrap();
    let separate_leaves = assert_outputs(
        &arena,
        &separate,
        &requirements,
        &retained,
        &first_evaluations,
    );

    let fused = PreparedProgressiveLeaves::prepare_with_mode_and_ntt_fusion(
        &arena,
        &requirements,
        &slots,
        &coefficients,
        &retained,
        arena.bind(TWIDDLES).unwrap(),
        ProgressiveCommitMode::DomainProgressive,
        ProgressiveNttLeafFusionMode::Fused16,
    )
    .unwrap();
    let topology = fused.launch_sequence().collect::<Vec<_>>();
    assert_eq!(
        topology
            .iter()
            .filter(|launch| matches!(launch, ProgressiveLeafLaunchKind::FusedLdeAbsorb { .. }))
            .count(),
        2
    );
    assert!(!topology.iter().any(|launch| matches!(
        launch,
        ProgressiveLeafLaunchKind::Lde { .. } | ProgressiveLeafLaunchKind::Absorb { .. }
    )));
    let telemetry = fused.ntt_leaf_fusion_telemetry();
    assert_eq!(telemetry.fused_blocks, 2);
    assert_eq!(telemetry.fused_columns, 32);
    assert_eq!(telemetry.separate_columns, 0);
    assert_eq!(telemetry.completed_lde_hash_read_bytes_avoided, 1 << 20);
    assert_eq!(telemetry.completed_lde_write_bytes_avoided, 12 * (1 << 15));
    assert_eq!(telemetry.retained_completed_lde_write_bytes, 20 * (1 << 15));
    fused.launch().unwrap();
    let fused_eager = assert_outputs(&arena, &fused, &requirements, &retained, &first_evaluations);
    assert_eq!(fused_eager, separate_leaves);

    let capture = arena.context().capture().unwrap();
    fused.launch().unwrap();
    let graph = capture.finish().unwrap();
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        assert_outputs(&arena, &fused, &requirements, &retained, &first_evaluations,),
        fused_eager
    );

    let second_coefficients = coefficient_set(&requirements, 91_337_123);
    for (column, words) in requirements.plan.columns.iter().zip(&second_coefficients) {
        upload(
            &arena,
            ArenaSlotId(SOURCE_BASE + column.canonical_index as u32),
            words,
        );
    }
    graph.launch(arena.context()).unwrap();
    let second_evaluations = expected_evaluations(&requirements, &second_coefficients);
    let replayed = assert_outputs(
        &arena,
        &fused,
        &requirements,
        &retained,
        &second_evaluations,
    );
    assert_ne!(replayed, fused_eager);
    assert_eq!(fused.launch_sequence().collect::<Vec<_>>(), topology);
}

#[test]
fn empty_message_finalize_matches_conventional_blake2s() {
    const STATE: ArenaSlotId = ArenaSlotId(1);
    const HASH: ArenaSlotId = ArenaSlotId(2);
    let state_words =
        core::mem::size_of::<stwo_backend_cuda_kernels::raw::ProgressiveBlake2sState>()
            / core::mem::size_of::<u32>();
    let layout = ArenaLayout::new(
        state_words + 8,
        &[
            ArenaSlotSpec {
                id: STATE,
                offset_words: 0,
                len_words: state_words,
                alignment_words: 1,
            },
            ArenaSlotSpec {
                id: HASH,
                offset_words: state_words,
                len_words: 8,
                alignment_words: 1,
            },
        ],
    )
    .unwrap();
    let arena = DeviceArena::new(CudaExecContext::new().unwrap(), layout).unwrap();
    let stream = arena.context().stream_raw().as_ptr();
    let state = arena.bind(STATE).unwrap();
    let hash = arena.bind(HASH).unwrap();
    unsafe {
        assert_eq!(
            stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_init_on(
                1,
                state.as_u32_ptr().cast(),
                stream,
            ),
            0
        );
        assert_eq!(
            stwo_backend_cuda_kernels::raw::stwo_blake2s_progressive_finalize_on(
                1,
                0,
                state.as_u32_ptr().cast(),
                hash.as_u32_ptr().cast(),
                stream,
            ),
            0
        );
    }
    assert_eq!(
        read_hashes(&arena, hash),
        vec![Blake2sHasherGeneric::<false>::default().finalize()]
    );
}
