//! Native CUDA correctness and capture gate for the prepared mixed-log commit.
//!
//! Hardware admission must require exactly one passed test from this target;
//! a CPU/stub build compiles zero tests and is not soundness evidence.

#![cfg(stwo_cuda_link)]

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo::prover::vcs_lifted::ops::MerkleOpsLifted;
use stwo_backend_cuda::{
    commit_workspace_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CommitArenaSlotRequirement, CommitBatchSlots, CommitCoefficientColumn, CommitCoefficientGroup,
    CommitEvaluationGroup, CommitGroupSlots, CommitLaunchKind, CommitLeafUpdateMode,
    CommitWorkspaceConfig, CommitWorkspaceRequirements, CommitWorkspaceSlots, CudaExecContext,
    DeviceArena, PreparedCommitGraph, RetainedLdeHashMode, COMMIT_HASH_ALIGNMENT_WORDS,
    COMMIT_POINTER_ALIGNMENT_WORDS,
};

const TWIDDLES: ArenaSlotId = ArenaSlotId(50_000);
const SOURCE_BASE: u32 = 51_000;
const EVALUATION_BASE: u32 = 70_000;

fn workspace_slots(requirements: &CommitWorkspaceRequirements) -> CommitWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    CommitWorkspaceSlots {
        lde_tile: id(),
        leaf_state: id(),
        merkle_scratch: requirements.merkle_scratch_words.map(|_| id()),
        retained_layers: requirements.retained_layers.iter().map(|_| id()).collect(),
        tail_level_ptrs: requirements.tail_pointer_words.map(|_| id()),
        tail_outputs: requirements.tail_outputs.iter().map(|_| id()).collect(),
        groups: requirements
            .groups
            .iter()
            .map(|group| CommitGroupSlots {
                column_ptrs: id(),
                column_log_sizes: id(),
                batches: group
                    .batches
                    .iter()
                    .map(|_| CommitBatchSlots {
                        coefficient_ptrs: id(),
                        coefficient_sizes: id(),
                        output_ptrs: id(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn arena(
    requirements: &CommitWorkspaceRequirements,
    slots: &CommitWorkspaceSlots,
    logs: &[u32],
    retained_evaluation_logs: &[u32],
    twiddle_words: usize,
) -> DeviceArena {
    let mut requested = requirements.arena_slot_requirements(slots).unwrap();
    requested.push(CommitArenaSlotRequirement {
        id: TWIDDLES,
        len_words: twiddle_words,
        alignment_words: 1,
    });
    requested.extend(logs.iter().enumerate().map(|(index, &log_size)| {
        CommitArenaSlotRequirement {
            id: ArenaSlotId(SOURCE_BASE + index as u32),
            len_words: 1usize << log_size,
            alignment_words: 1,
        }
    }));
    requested.extend(
        retained_evaluation_logs
            .iter()
            .enumerate()
            .map(|(index, &log_size)| CommitArenaSlotRequirement {
                id: ArenaSlotId(EVALUATION_BASE + index as u32),
                len_words: 1usize << log_size,
                alignment_words: 1,
            }),
    );

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
    assert!(destination.len_words() >= words.len());
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
    let count = source.len_words() / 8;
    let mut hashes = vec![Blake2sHash::default(); count];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                hashes.as_mut_ptr().cast(),
                source.as_void_ptr(),
                count * core::mem::size_of::<Blake2sHash>(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    hashes
}

fn read_words(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut words = vec![0u32; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                source.as_void_ptr(),
                core::mem::size_of_val(words.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
}

fn coefficient_set(logs: &[u32], seed: u32) -> Vec<Vec<u32>> {
    logs.iter()
        .enumerate()
        .map(|(column, &log_size)| {
            (0..1usize << log_size)
                .map(|index| {
                    (seed as u64 + 104_729u64 * (column as u64 + 1) + 7_919u64 * index as u64)
                        .rem_euclid(0x7fff_ffff) as u32
                })
                .collect()
        })
        .collect()
}

fn cpu_evaluations(
    config: CommitWorkspaceConfig,
    logs: &[u32],
    coefficients: &[Vec<u32>],
) -> Vec<Vec<BaseField>> {
    let full_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
    let twiddles = CpuBackend::precompute_twiddles(full_domain.half_coset);
    logs.iter()
        .zip(coefficients)
        .map(|(&log_size, words)| {
            CircleCoefficients::<CpuBackend>::new(
                words
                    .iter()
                    .copied()
                    .map(BaseField::from_u32_unchecked)
                    .collect(),
            )
            .evaluate_with_twiddles(
                CanonicCoset::new(log_size + config.log_blowup_factor).circle_domain(),
                &twiddles,
            )
            .values
        })
        .collect()
}

fn cpu_layers(
    config: CommitWorkspaceConfig,
    logs: &[u32],
    coefficients: &[Vec<u32>],
) -> Vec<Vec<Blake2sHash>> {
    let evaluations = cpu_evaluations(config, logs, coefficients);
    let columns = evaluations.iter().collect::<Vec<_>>();
    let mut layers = vec![
        <CpuBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_leaves(
            &columns,
            config.lifting_log_size,
        ),
    ];
    while layers.last().unwrap().len() > 1 {
        layers.push(
            <CpuBackend as MerkleOpsLifted<Blake2sMerkleHasher>>::build_next_layer(
                layers.last().unwrap(),
            ),
        );
    }
    layers
}

fn assert_retained_evaluations(
    arena: &DeviceArena,
    prepared: &PreparedCommitGraph<'_>,
    config: CommitWorkspaceConfig,
    logs: &[u32],
    coefficients: &[Vec<u32>],
) {
    let expected = cpu_evaluations(config, logs, coefficients);
    assert!(prepared.retained_evaluations()[0].is_none());
    let retained = prepared.retained_evaluations()[1].as_ref().unwrap();
    assert!(prepared.retained_evaluations()[2].is_none());
    assert_eq!(retained.len(), 16);
    for (actual, expected) in retained.iter().copied().zip(&expected[16..32]) {
        assert_eq!(
            read_words(arena, actual),
            expected.iter().map(|value| value.0).collect::<Vec<_>>()
        );
    }
}

fn assert_all_retained_layers(
    arena: &DeviceArena,
    prepared: &PreparedCommitGraph<'_>,
    expected: &[Vec<Blake2sHash>],
) {
    assert_eq!(prepared.retained_layers_bottom_up().len(), expected.len());
    for (actual, expected) in prepared
        .retained_layers_bottom_up()
        .iter()
        .copied()
        .zip(expected)
    {
        assert_eq!(read_hashes(arena, actual), *expected);
    }
    assert_eq!(
        prepared.read_root_at_transcript_boundary().unwrap(),
        expected.last().unwrap()[0]
    );
}

/// Step 3.2 interior four-level fusion gate: the SAME pruned commitment runs
/// with the fused interior lane pinned OFF and ON in one invocation (the
/// `STWO_CUDA_BLAKE2S_INTERIOR_FUSED` switch is a process-global OnceLock, so
/// both variants are exercised via the explicit-mode constructor regardless of
/// the environment). Asserts the per-mode interior node budgets (10 per-level
/// interior nodes vs 1 fused + 6 per-level), byte-identical retained layers
/// against the CPU reference in both modes, equal roots, and graph-capture
/// replay identity for the fused topology.
#[test]
fn pruned_commit_interior_fused_and_per_level_match_cpu() {
    let config = CommitWorkspaceConfig {
        log_blowup_factor: 1,
        lifting_log_size: 13,
        unretained_bottom_layers: 4,
        max_fused_tail_levels: 3,
    };
    // 16-column update group + 3-column final group, all log 12 (+1 blowup =
    // lifting). Prune depth 4: interior levels 0..10 (logs 12..3), levels
    // 0,1,2 unretained; the fused window's output (log 9) is the first
    // retained layer. Tail covers logs 2..0.
    let grouped_logs = [vec![12; 16], vec![12; 3]];
    let logs = grouped_logs.iter().flatten().copied().collect::<Vec<_>>();
    let requirements = commit_workspace_requirements(config, &grouped_logs).unwrap();
    let slots = workspace_slots(&requirements);
    let twiddle_words = 1usize << (config.lifting_log_size - 1);
    let arena = arena(&requirements, &slots, &logs, &[], twiddle_words);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(config.lifting_log_size)
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
    let coefficients = coefficient_set(&logs, 4242);
    for (index, words) in coefficients.iter().enumerate() {
        upload(&arena, ArenaSlotId(SOURCE_BASE + index as u32), words);
    }

    let groups = grouped_logs
        .iter()
        .scan(0usize, |first, group_logs| {
            let columns = group_logs
                .iter()
                .enumerate()
                .map(|(offset, &log_size)| CommitCoefficientColumn {
                    coefficients: arena
                        .bind(ArenaSlotId(SOURCE_BASE + (*first + offset) as u32))
                        .unwrap(),
                    log_size,
                })
                .collect();
            *first += group_logs.len();
            Some(CommitCoefficientGroup { columns })
        })
        .collect::<Vec<_>>();

    // The retained set: everything from the first retained interior layer
    // (log 9) up to the root. cpu_layers[k] has log 13 - k.
    let expected = cpu_layers(config, &logs, &coefficients);
    let expected_retained = &expected[config.unretained_bottom_layers as usize..];

    let interior_kinds = |prepared: &PreparedCommitGraph<'_>| {
        prepared
            .launch_sequence()
            .filter(|kind| {
                matches!(
                    kind,
                    CommitLaunchKind::InteriorLayer { .. }
                        | CommitLaunchKind::FusedInterior4 { .. }
                )
            })
            .collect::<Vec<_>>()
    };

    // Both modes reuse the same arena buffers, so poison every retained layer
    // before each run — a mode only passes if IT wrote the bytes.
    let scramble_retained_layers = || {
        for &slot in slots.retained_layers.iter().chain(&slots.tail_outputs) {
            let words = arena.bind(slot).unwrap().len_words();
            upload(&arena, slot, &vec![0xDEAD_BEEFu32; words]);
        }
        arena.context().sync().unwrap();
    };

    let mut roots = Vec::new();
    for interior_fused in [false, true] {
        let prepared = PreparedCommitGraph::prepare_with_interior_mode(
            &arena,
            config,
            &groups,
            arena.bind(TWIDDLES).unwrap(),
            &slots,
            interior_fused,
        )
        .unwrap();

        // Node budgets: per-level = one launch per interior level; fused =
        // the bottom four levels in one node, retained levels per-level.
        let kinds = interior_kinds(&prepared);
        if interior_fused {
            assert_eq!(kinds.len(), 7, "fused interior node budget");
            assert_eq!(
                kinds[0],
                CommitLaunchKind::FusedInterior4 {
                    first_level: 0,
                    output_hashes: 1 << 9,
                }
            );
            assert!(kinds[1..]
                .iter()
                .all(|kind| matches!(kind, CommitLaunchKind::InteriorLayer { .. })));
        } else {
            assert_eq!(kinds.len(), 10, "per-level interior node budget");
            assert!(kinds
                .iter()
                .all(|kind| matches!(kind, CommitLaunchKind::InteriorLayer { .. })));
        }

        scramble_retained_layers();
        prepared.launch().unwrap();
        assert_all_retained_layers(&arena, &prepared, expected_retained);
        roots.push(prepared.read_root_at_transcript_boundary().unwrap());

        // Graph capture replays the identical fused topology byte-for-byte.
        if interior_fused {
            let capture = arena.context().capture().unwrap();
            prepared.launch().unwrap();
            let graph = capture.finish().unwrap();
            scramble_retained_layers();
            graph.launch(arena.context()).unwrap();
            assert_all_retained_layers(&arena, &prepared, expected_retained);
        }
    }
    assert_eq!(roots[0], roots[1], "fused and per-level roots must agree");
}

#[test]
fn mixed_log_commit_eager_and_capture_match_cpu_leaf_and_every_layer() {
    let config = CommitWorkspaceConfig {
        log_blowup_factor: 1,
        lifting_log_size: 13,
        unretained_bottom_layers: 0,
        max_fused_tail_levels: 3,
    };
    let grouped_logs = [vec![4; 16], vec![12; 16], vec![12; 16]];
    let logs = grouped_logs.iter().flatten().copied().collect::<Vec<_>>();
    let requirements = commit_workspace_requirements(config, &grouped_logs).unwrap();
    let slots = workspace_slots(&requirements);
    let twiddle_words = 1usize << (config.lifting_log_size - 1);
    let retained_evaluation_logs = grouped_logs[1]
        .iter()
        .map(|log| log + config.log_blowup_factor)
        .collect::<Vec<_>>();
    let arena = arena(
        &requirements,
        &slots,
        &logs,
        &retained_evaluation_logs,
        twiddle_words,
    );
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(config.lifting_log_size)
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

    let groups = grouped_logs
        .iter()
        .scan(0usize, |first, group_logs| {
            let columns = group_logs
                .iter()
                .enumerate()
                .map(|(offset, &log_size)| CommitCoefficientColumn {
                    coefficients: arena
                        .bind(ArenaSlotId(SOURCE_BASE + (*first + offset) as u32))
                        .unwrap(),
                    log_size,
                })
                .collect();
            *first += group_logs.len();
            Some(CommitCoefficientGroup { columns })
        })
        .collect::<Vec<_>>();
    let retained_outputs = [
        None,
        Some(CommitEvaluationGroup {
            columns: (0..grouped_logs[1].len())
                .map(|index| {
                    arena
                        .bind(ArenaSlotId(EVALUATION_BASE + index as u32))
                        .unwrap()
                })
                .collect(),
        }),
        None,
    ];
    let prepared = PreparedCommitGraph::prepare_with_retained_evaluations(
        &arena,
        config,
        &groups,
        arena.bind(TWIDDLES).unwrap(),
        &slots,
        &retained_outputs,
    )
    .unwrap();

    let fusion = prepared.hash_from_tile_telemetry();
    assert_eq!(fusion.fused_groups, 2);
    assert_eq!(fusion.fused_columns, 32);
    assert_eq!(fusion.unfused_groups, 1);
    assert_eq!(
        fusion.bytes_avoided,
        logs[..16]
            .iter()
            .chain(&logs[32..])
            .map(|&log_size| 8u64 << (log_size + config.log_blowup_factor))
            .sum::<u64>()
    );
    assert_eq!(
        prepared
            .launch_sequence()
            .filter(|kind| matches!(kind, CommitLaunchKind::NttHash { .. }))
            .count(),
        1,
        "the counted native gate must execute the optimized producer-fused lane"
    );

    // Leaf + one layer per log down to the root are all retained in this gate.
    assert_eq!(prepared.retained_layers_bottom_up().len(), 14);
    assert_eq!(COMMIT_HASH_ALIGNMENT_WORDS, 8);
    assert_eq!(COMMIT_POINTER_ALIGNMENT_WORDS, 2);

    let first = coefficient_set(&logs, 17);
    for (index, words) in first.iter().enumerate() {
        upload(&arena, ArenaSlotId(SOURCE_BASE + index as u32), words);
    }
    prepared.launch().unwrap();
    assert_all_retained_layers(&arena, &prepared, &cpu_layers(config, &logs, &first));
    assert_retained_evaluations(&arena, &prepared, config, &logs, &first);

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    graph.launch(arena.context()).unwrap();
    assert_all_retained_layers(&arena, &prepared, &cpu_layers(config, &logs, &first));
    assert_retained_evaluations(&arena, &prepared, config, &logs, &first);

    let second = coefficient_set(&logs, 0x1234_5678);
    for (index, words) in second.iter().enumerate() {
        upload(&arena, ArenaSlotId(SOURCE_BASE + index as u32), words);
    }
    graph.launch(arena.context()).unwrap();
    assert_all_retained_layers(&arena, &prepared, &cpu_layers(config, &logs, &second));
    assert_retained_evaluations(&arena, &prepared, config, &logs, &second);
    drop(graph);
    drop(prepared);

    // Step 3.1 retained LDE-write + leaf-absorb gate: the SAME retained
    // commitment runs with scalar, cooperative-quad, and retained-fused
    // topologies pinned explicitly in one invocation. The fused plan replaces
    // the retained group's Lde + LeafUpdate
    // launch pair with one RetainedNttHash node and must reproduce the
    // Separate plan's retained evaluations, every retained layer, and the
    // root byte-for-byte — eagerly and through mutated graph replay. Both
    // modes reuse the same arena buffers, so every output (retained layers,
    // leaf states, retained evaluations) is poisoned before each run: a mode
    // only passes if IT wrote the bytes.
    let scramble_outputs = || {
        for &slot in slots
            .retained_layers
            .iter()
            .chain(&slots.tail_outputs)
            .chain(core::iter::once(&slots.leaf_state))
        {
            let words = arena.bind(slot).unwrap().len_words();
            upload(&arena, slot, &vec![0xDEAD_BEEFu32; words]);
        }
        for index in 0..grouped_logs[1].len() {
            let slot = ArenaSlotId(EVALUATION_BASE + index as u32);
            let words = arena.bind(slot).unwrap().len_words();
            upload(&arena, slot, &vec![0xDEAD_BEEFu32; words]);
        }
        arena.context().sync().unwrap();
    };

    let third = coefficient_set(&logs, 0x9e37_79b9);
    let mut launch_counts = Vec::new();
    for (retained_mode, leaf_mode) in [
        (RetainedLdeHashMode::Separate, CommitLeafUpdateMode::Scalar),
        (RetainedLdeHashMode::Separate, CommitLeafUpdateMode::Quad),
        (RetainedLdeHashMode::Fused, CommitLeafUpdateMode::Scalar),
    ] {
        let prepared = PreparedCommitGraph::prepare_with_retained_evaluations_and_modes(
            &arena,
            config,
            &groups,
            arena.bind(TWIDDLES).unwrap(),
            &slots,
            &retained_outputs,
            retained_mode,
            leaf_mode,
        )
        .unwrap();
        launch_counts.push(prepared.launch_sequence().len());

        let retained_ntt_nodes = prepared
            .launch_sequence()
            .filter(|kind| matches!(kind, CommitLaunchKind::RetainedNttHash { .. }))
            .count();
        let telemetry = prepared.hash_from_tile_telemetry();
        if retained_mode == RetainedLdeHashMode::Fused {
            assert_eq!(
                retained_ntt_nodes, 1,
                "the retained group must take the fused write+hash lane"
            );
            assert_eq!(telemetry.retained_fused_groups, 1);
            assert_eq!(telemetry.unfused_groups, 0);
        } else {
            assert_eq!(retained_ntt_nodes, 0);
            assert_eq!(telemetry.retained_fused_groups, 0);
            assert_eq!(telemetry.unfused_groups, 1);
            assert!(prepared.launch_sequence().any(|launch| {
                matches!(launch, CommitLaunchKind::LeafUpdate { mode, .. } if mode == leaf_mode)
            }));
        }

        // The previous mode's graph replay mutates the shared source slots to
        // `first`. Restore this mode's eager fixture before comparing it with
        // the `third` CPU oracle.
        for (index, words) in third.iter().enumerate() {
            upload(&arena, ArenaSlotId(SOURCE_BASE + index as u32), words);
        }
        scramble_outputs();
        prepared.launch().unwrap();
        assert_all_retained_layers(&arena, &prepared, &cpu_layers(config, &logs, &third));
        assert_retained_evaluations(&arena, &prepared, config, &logs, &third);

        // Graph capture replays each new topology byte-for-byte on mutated
        // coefficients.
        if retained_mode == RetainedLdeHashMode::Fused || leaf_mode == CommitLeafUpdateMode::Quad {
            let capture = arena.context().capture().unwrap();
            prepared.launch().unwrap();
            let graph = capture.finish().unwrap();
            for (index, words) in first.iter().enumerate() {
                upload(&arena, ArenaSlotId(SOURCE_BASE + index as u32), words);
            }
            scramble_outputs();
            graph.launch(arena.context()).unwrap();
            assert_all_retained_layers(&arena, &prepared, &cpu_layers(config, &logs, &first));
            assert_retained_evaluations(&arena, &prepared, config, &logs, &first);
        }
    }
    // Capture node budget: the fused plan carries exactly one fewer launch —
    // the retained group's Lde + LeafUpdate pair became one RetainedNttHash.
    assert_eq!(launch_counts[0], launch_counts[1]);
    assert_eq!(launch_counts[2] + 1, launch_counts[0]);
}
