//! Native eager/capture differential for compact expand/absorb fusion.
//!
//! The materialized-only executor is compared with the ordinary compact graph
//! in independent arenas. Production terminal-fused shapes are rejected by the
//! binder and belong to the later composed executor gate.

use std::collections::BTreeMap;

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs::blake2_hash::Blake2sHash;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo_backend_cuda::{
    compact_domain_arena_slot_requirements, direct_compact_domain_arena_slot_requirements,
    full_lifting_leaf_oracle, fused_compact_domain_arena_slot_requirements,
    progressive_leaf_oracle, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CommitArenaSlotRequirement, CommitCoefficientColumn, CommitProgram, CommitWorkspaceConfig,
    CompactDomainProgram, CudaExecContext, DeviceArena, DirectCompactTerminalBatchMode,
    DirectCompactTerminalProgram, DirectRetainedB2nColumn, DirectRetainedB2nProgram,
    DomainCooperativeProgram, FusedCompactDomainProgram, MerkleFromLeavesSlots,
    PreparedCompactDomainCommitGraph, PreparedFusedCompactDomainCommitGraph, ProgressiveBatchSlots,
    ProgressiveCommitGeometry, ProgressiveCommitGroupGeometry,
    ProgressiveCommitWorkspaceRequirements, ProgressiveCommitWorkspaceSlots,
    ProgressiveLeafWorkspaceSlots, ProgressiveNttLeafFusionMode, TraceTreeRole,
};

const TWIDDLES: ArenaSlotId = ArenaSlotId(50_000);
const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(50_001);
const COEFFICIENT_BASE: u32 = 51_000;
const OUTPUT_BASE: u32 = 52_000;

#[derive(Clone)]
struct Case {
    name: &'static str,
    lifting_log_size: u32,
    groups: Vec<Vec<u32>>,
    transitions: usize,
}

fn programs(
    case: &Case,
) -> (
    CommitProgram,
    DomainCooperativeProgram,
    CompactDomainProgram,
    FusedCompactDomainProgram,
    DirectRetainedB2nProgram,
    DirectCompactTerminalProgram,
) {
    let base = CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: case.lifting_log_size,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: case.lifting_log_size,
            log_blowup_factor: 1,
            groups: case
                .groups
                .iter()
                .map(|logs| ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: logs.clone(),
                    retain_evaluations: true,
                })
                .collect(),
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let domain = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let compact = CompactDomainProgram::compile(&base, &domain).unwrap();
    let fused = FusedCompactDomainProgram::compile(&base, &domain, &compact).unwrap();
    let direct = DirectRetainedB2nProgram::compile(TraceTreeRole::Base, &base).unwrap();
    let terminal = DirectCompactTerminalProgram::compile(&compact, &direct).unwrap();
    assert_eq!(
        fused.receipt().transitions.len(),
        case.transitions,
        "{}",
        case.name
    );
    (base, domain, compact, fused, direct, terminal)
}

fn slots(requirements: &ProgressiveCommitWorkspaceRequirements) -> ProgressiveCommitWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    let slab = id();
    ProgressiveCommitWorkspaceSlots {
        leaves: ProgressiveLeafWorkspaceSlots {
            lde_scratch: requirements.leaves.lde_scratch_words.map(|_| id()),
            state_ping: slab,
            state_pong: requirements.leaves.state_pong_words.map(|_| slab),
            leaf_hashes: slab,
            batches: requirements
                .leaves
                .batches
                .iter()
                .map(|_| ProgressiveBatchSlots {
                    coefficient_ptrs: id(),
                    coefficient_sizes: id(),
                    output_ptrs: id(),
                })
                .collect(),
        },
        merkle: MerkleFromLeavesSlots {
            leaves: slab,
            merkle_scratch: requirements.merkle.merkle_scratch_words.map(|_| slab),
            retained_layers: requirements
                .merkle
                .retained_layers
                .iter()
                .map(|_| id())
                .collect(),
            tail_level_ptrs: requirements.merkle.tail_pointer_words.map(|_| id()),
            tail_outputs: requirements
                .merkle
                .tail_outputs
                .iter()
                .map(|_| id())
                .collect(),
        },
    }
}

fn insert(
    requirements: &mut BTreeMap<ArenaSlotId, (usize, usize)>,
    requirement: CommitArenaSlotRequirement,
) {
    requirements
        .entry(requirement.id)
        .and_modify(|current| {
            current.0 = current.0.max(requirement.len_words);
            current.1 = current.1.max(requirement.alignment_words);
        })
        .or_insert((requirement.len_words, requirement.alignment_words));
}

fn arena(base: &CommitProgram, workspace: Vec<CommitArenaSlotRequirement>) -> DeviceArena {
    let mut requirements = BTreeMap::new();
    for requirement in workspace {
        insert(&mut requirements, requirement);
    }
    for id in [TWIDDLES, INVERSE_TWIDDLES] {
        insert(
            &mut requirements,
            CommitArenaSlotRequirement {
                id,
                len_words: base.requirements().leaves.twiddle_words,
                alignment_words: 1,
            },
        );
    }
    for column in &base.requirements().leaves.plan.columns {
        for (id, len_words) in [
            (
                ArenaSlotId(COEFFICIENT_BASE + column.canonical_index as u32),
                1usize << column.coefficient_log_size,
            ),
            (
                ArenaSlotId(OUTPUT_BASE + column.canonical_index as u32),
                1usize << column.evaluation_log_size,
            ),
        ] {
            insert(
                &mut requirements,
                CommitArenaSlotRequirement {
                    id,
                    len_words,
                    alignment_words: 1,
                },
            );
        }
    }
    let mut offset_words = 0usize;
    let specs = requirements
        .into_iter()
        .map(|(id, (len_words, alignment_words))| {
            offset_words = offset_words.next_multiple_of(alignment_words);
            let spec = ArenaSlotSpec {
                id,
                offset_words,
                len_words,
                alignment_words,
            };
            offset_words += len_words;
            spec
        })
        .collect::<Vec<_>>();
    DeviceArena::new(
        CudaExecContext::new().unwrap(),
        ArenaLayout::new(offset_words, &specs).unwrap(),
    )
    .unwrap()
}

fn upload(arena: &DeviceArena, destination: ArenaSlice, words: &[u32]) {
    assert_eq!(destination.len_words(), words.len());
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
    let mut hashes = vec![Blake2sHash::default(); source.len_words() / 8];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                hashes.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(hashes.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    hashes
}

fn read_words(arena: &DeviceArena, source: ArenaSlice) -> Vec<u32> {
    let mut words = vec![0; source.len_words()];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(words.as_slice()),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
}

fn coefficients(base: &CommitProgram, seed: u64) -> Vec<Vec<u32>> {
    base.requirements()
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| {
            (0..1usize << column.coefficient_log_size)
                .map(|row| {
                    (seed
                        .wrapping_add((column.canonical_index as u64 + 1) * 104_729)
                        .wrapping_add(row as u64 * 7_919)
                        % 0x7fff_ffff) as u32
                })
                .collect()
        })
        .collect()
}

fn evaluations(base: &CommitProgram, coefficients: &[Vec<u32>]) -> Vec<Vec<u32>> {
    base.requirements()
        .leaves
        .plan
        .columns
        .iter()
        .zip(coefficients)
        .map(|(column, words)| {
            let domain = CanonicCoset::new(column.evaluation_log_size).circle_domain();
            let twiddles = CpuBackend::precompute_twiddles(domain.half_coset);
            CircleCoefficients::<CpuBackend>::new(
                words
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
        })
        .collect()
}

fn seed_arena(
    arena: &DeviceArena,
    base: &CommitProgram,
    coefficient_words: &[Vec<u32>],
) -> (Vec<CommitCoefficientColumn>, Vec<Option<ArenaSlice>>) {
    let domain = CanonicCoset::new(base.identity().geometry.lifting_log_size).circle_domain();
    let twiddle_tree = CpuBackend::precompute_twiddles(domain.half_coset);
    let twiddles = twiddle_tree
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let inverse_twiddles = twiddle_tree
        .itwiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    upload(arena, arena.bind(TWIDDLES).unwrap(), &twiddles);
    upload(
        arena,
        arena.bind(INVERSE_TWIDDLES).unwrap(),
        &inverse_twiddles,
    );
    let columns = base
        .requirements()
        .leaves
        .plan
        .columns
        .iter()
        .zip(coefficient_words)
        .map(|(column, words)| {
            let source = arena
                .bind(ArenaSlotId(
                    COEFFICIENT_BASE + column.canonical_index as u32,
                ))
                .unwrap();
            upload(arena, source, words);
            CommitCoefficientColumn {
                coefficients: source,
                log_size: column.coefficient_log_size,
            }
        })
        .collect::<Vec<_>>();
    let retained = base
        .requirements()
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| {
            Some(
                arena
                    .bind(ArenaSlotId(OUTPUT_BASE + column.canonical_index as u32))
                    .unwrap(),
            )
        })
        .collect();
    arena.context().sync().unwrap();
    (columns, retained)
}

fn seed_direct_arena(
    arena: &DeviceArena,
    base: &CommitProgram,
    source_evaluations: &[Vec<u32>],
) -> Vec<DirectRetainedB2nColumn> {
    let (_, retained) = seed_arena(arena, base, source_evaluations);
    base.requirements()
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| DirectRetainedB2nColumn {
            source_evaluations: arena
                .bind(ArenaSlotId(
                    COEFFICIENT_BASE + column.canonical_index as u32,
                ))
                .unwrap(),
            retained_output: retained[column.canonical_index].unwrap(),
        })
        .collect()
}

fn assert_outputs(
    base: &CommitProgram,
    evaluations: &[Vec<u32>],
    arena: &DeviceArena,
    leaves: ArenaSlice,
    retained: &[Option<ArenaSlice>],
) -> Vec<Blake2sHash> {
    let actual = read_hashes(arena, leaves);
    assert_eq!(
        actual,
        progressive_leaf_oracle(&base.requirements().leaves.plan, evaluations).unwrap()
    );
    assert_eq!(
        actual,
        full_lifting_leaf_oracle(&base.requirements().leaves.plan, evaluations).unwrap()
    );
    for (expected, output) in evaluations.iter().zip(retained) {
        assert_eq!(&read_words(arena, output.unwrap()), expected);
    }
    actual
}

fn assert_direct_outputs(
    base: &CommitProgram,
    evaluations: &[Vec<u32>],
    arena: &DeviceArena,
    leaves: ArenaSlice,
    retained: &[Option<ArenaSlice>],
) -> Vec<Blake2sHash> {
    if base.identity().geometry.lifting_log_size <= 16 {
        return assert_outputs(base, evaluations, arena, leaves, retained);
    }
    for (expected, output) in evaluations.iter().zip(retained) {
        assert_eq!(&read_words(arena, output.unwrap()), expected);
    }
    read_hashes(arena, leaves)
}

fn run(case: Case) {
    let (base, domain, compact, fused, direct, terminal) = programs(&case);
    let workspace_slots = slots(base.requirements());
    let baseline_arena = arena(
        &base,
        compact_domain_arena_slot_requirements(&compact, &base, &domain, &workspace_slots).unwrap(),
    );
    let candidate_arena = arena(
        &base,
        fused_compact_domain_arena_slot_requirements(
            &fused,
            &base,
            &domain,
            &compact,
            &workspace_slots,
        )
        .unwrap(),
    );
    let first_coefficients = coefficients(&base, 0x51ab_1eaf);
    let first_evaluations = evaluations(&base, &first_coefficients);
    let (baseline_columns, baseline_retained) =
        seed_arena(&baseline_arena, &base, &first_coefficients);
    let (candidate_columns, candidate_retained) =
        seed_arena(&candidate_arena, &base, &first_coefficients);
    let baseline: PreparedCompactDomainCommitGraph<'_> = compact
        .bind_prepared(
            &baseline_arena,
            &base,
            &domain,
            &workspace_slots,
            &baseline_columns,
            &baseline_retained,
            baseline_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();
    let candidate: PreparedFusedCompactDomainCommitGraph<'_> = fused
        .bind_prepared_materialized_only(
            &candidate_arena,
            &base,
            &domain,
            &compact,
            &direct,
            &terminal,
            &workspace_slots,
            &candidate_columns,
            &candidate_retained,
            candidate_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();

    baseline.launch().unwrap();
    candidate.launch().unwrap();
    let eager_baseline = assert_direct_outputs(
        &base,
        &first_evaluations,
        &baseline_arena,
        baseline.leaf_hashes(),
        &baseline_retained,
    );
    let eager_candidate = assert_direct_outputs(
        &base,
        &first_evaluations,
        &candidate_arena,
        candidate.leaf_hashes(),
        &candidate_retained,
    );
    assert_eq!(
        eager_candidate, eager_baseline,
        "{} eager leaves",
        case.name
    );
    assert_eq!(
        candidate.read_root_at_transcript_boundary().unwrap(),
        baseline.read_root_at_transcript_boundary().unwrap(),
        "{} eager root",
        case.name
    );

    let capture = baseline_arena.context().capture().unwrap();
    baseline.launch().unwrap();
    let baseline_graph = capture.finish().unwrap();
    let capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    let expected_saved = fused
        .receipt()
        .transitions
        .iter()
        .map(|transition| u64::from(transition.expansion_bands))
        .sum::<u64>();
    assert_eq!(
        baseline_graph.kernel_nodes() - candidate_graph.kernel_nodes(),
        expected_saved,
        "{} captured kernel savings",
        case.name
    );
    baseline_graph.launch(baseline_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    assert_eq!(
        assert_direct_outputs(
            &base,
            &first_evaluations,
            &candidate_arena,
            candidate.leaf_hashes(),
            &candidate_retained,
        ),
        eager_candidate,
        "{} replay",
        case.name
    );

    let second_coefficients = coefficients(&base, 0xc001_cafe);
    for ((column, baseline), candidate) in base
        .requirements()
        .leaves
        .plan
        .columns
        .iter()
        .zip(&baseline_columns)
        .zip(&candidate_columns)
    {
        let words = &second_coefficients[column.canonical_index];
        upload(&baseline_arena, baseline.coefficients, words);
        upload(&candidate_arena, candidate.coefficients, words);
    }
    baseline_graph.launch(baseline_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let second_evaluations = evaluations(&base, &second_coefficients);
    let mutated_baseline = assert_direct_outputs(
        &base,
        &second_evaluations,
        &baseline_arena,
        baseline.leaf_hashes(),
        &baseline_retained,
    );
    let mutated_candidate = assert_direct_outputs(
        &base,
        &second_evaluations,
        &candidate_arena,
        candidate.leaf_hashes(),
        &candidate_retained,
    );
    assert_eq!(
        mutated_candidate, mutated_baseline,
        "{} mutation",
        case.name
    );
    assert_ne!(
        mutated_candidate, eager_candidate,
        "{} stale replay",
        case.name
    );
    assert_eq!(
        candidate.read_root_at_transcript_boundary().unwrap(),
        baseline.read_root_at_transcript_boundary().unwrap(),
        "{} mutated root",
        case.name
    );
}

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires native CUDA")]
fn fused_expand_absorb_matches_legacy_eager_capture_and_mutation() {
    assert!(stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT);
    for case in [
        Case {
            name: "zero-transition",
            lifting_log_size: 5,
            groups: vec![vec![4; 17]],
            transitions: 0,
        },
        Case {
            name: "tail16-odd",
            lifting_log_size: 5,
            groups: vec![vec![3; 16], vec![4; 1]],
            transitions: 1,
        },
        Case {
            name: "tail32-odd",
            lifting_log_size: 5,
            groups: vec![vec![3; 32], vec![4; 1]],
            transitions: 1,
        },
        Case {
            name: "tail33-multilog",
            lifting_log_size: 7,
            groups: vec![vec![3; 33], vec![6; 1]],
            transitions: 1,
        },
        Case {
            name: "even-two-transition",
            lifting_log_size: 7,
            groups: vec![vec![3; 17], vec![4; 16], vec![6; 1]],
            transitions: 2,
        },
    ] {
        run(case);
    }
}

fn run_direct_terminal(
    case: Case,
    expected_fixed_columns: u32,
    expected_tiles: u32,
    expected_expansions: u32,
    measure: bool,
) {
    assert!(stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT);
    let (base, domain, compact, _fused, direct, terminal) = programs(&case);
    let fixed_batches = terminal
        .receipt()
        .batches
        .iter()
        .filter(|batch| {
            matches!(
                batch.mode,
                DirectCompactTerminalBatchMode::Fixed16Hybrid { .. }
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(fixed_batches.len(), 1);
    let batch = fixed_batches[0];
    assert_eq!(
        batch.mode,
        DirectCompactTerminalBatchMode::Fixed16Hybrid {
            fixed_columns: expected_fixed_columns,
            tiles: expected_tiles,
            generic_remainder_columns: 0,
        }
    );
    let receipt = terminal.receipt();
    let removed_bytes = u64::from(expected_fixed_columns) * (1u64 << batch.log_size) * 4;
    let canonical_bytes = base
        .requirements()
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| (1u64 << column.evaluation_log_size) * 4)
        .sum::<u64>();
    let tail_words = stwo_backend_cuda_kernels::raw::blake2s_compact_tail_words(
        batch.first_column + expected_fixed_columns,
    );
    let tail_bytes =
        u64::from(tail_words) * u64::from(expected_tiles - 1) * (1u64 << batch.log_size) * 4;
    assert_eq!(receipt.separate_absorb_reread_bytes_removed, removed_bytes);
    assert_eq!(receipt.terminal_prefinal_read_bytes_added, 0);
    assert_eq!(receipt.compact_tail_reread_bytes_added, tail_bytes);
    assert_eq!(receipt.net_read_bytes_removed, removed_bytes - tail_bytes);
    assert_eq!(receipt.terminal_prefinal_write_bytes_added, 0);
    assert_eq!(receipt.net_device_bytes_removed, removed_bytes - tail_bytes);
    assert_eq!(
        receipt.canonical_retained_write_bytes_before,
        canonical_bytes
    );
    assert_eq!(
        receipt.canonical_retained_write_bytes_after,
        canonical_bytes
    );
    assert_eq!(receipt.separate_absorb_launches_removed, 1);
    assert_eq!(receipt.fixed_terminal_launches, 1);
    assert_eq!(receipt.extra_remainder_interval_launches, 0);
    assert_eq!(receipt.generic_remainder_terminal_launches, 0);
    assert_eq!(receipt.net_cuda_launches_removed, 1);
    assert_eq!(receipt.cooperative_quad_blake2s_batches, 1);
    assert_eq!(
        receipt.compact_expansion_launches_unchanged,
        expected_expansions
    );
    assert_eq!(receipt.compact_finalize_launches_unchanged, 1);
    assert!(receipt.merkle_suffix_unchanged);
    assert!(!receipt.same_gpu_timing_credit_applied);

    let workspace_slots = slots(base.requirements());
    let workspace = direct_compact_domain_arena_slot_requirements(
        &compact,
        &base,
        &domain,
        &direct,
        &workspace_slots,
    )
    .unwrap();
    let baseline_arena = arena(&base, workspace.clone());
    let candidate_arena = arena(&base, workspace);
    let first_sources = coefficients(&base, 0x51ab_1eaf);
    let first_oracle = direct.oracle(&first_sources).unwrap();
    let baseline_columns = seed_direct_arena(&baseline_arena, &base, &first_sources);
    let candidate_columns = seed_direct_arena(&candidate_arena, &base, &first_sources);

    let baseline = compact
        .bind_prepared_direct(
            &baseline_arena,
            &base,
            &domain,
            &direct,
            &workspace_slots,
            &baseline_columns,
            baseline_arena.bind(INVERSE_TWIDDLES).unwrap(),
            baseline_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();
    let candidate = compact
        .bind_prepared_direct_terminal_fused(
            &candidate_arena,
            &base,
            &domain,
            &direct,
            terminal,
            &workspace_slots,
            &candidate_columns,
            candidate_arena.bind(INVERSE_TWIDDLES).unwrap(),
            candidate_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();

    baseline.launch().unwrap();
    candidate.launch().unwrap();
    let eager_baseline = assert_direct_outputs(
        &base,
        &first_oracle.retained_evaluations,
        &baseline_arena,
        baseline.leaf_hashes(),
        baseline.retained_evaluations(),
    );
    let eager_candidate = assert_direct_outputs(
        &base,
        &first_oracle.retained_evaluations,
        &candidate_arena,
        candidate.leaf_hashes(),
        candidate.retained_evaluations(),
    );
    assert_eq!(
        eager_candidate, eager_baseline,
        "{} eager leaves",
        case.name
    );
    assert_eq!(
        candidate.read_root_at_transcript_boundary().unwrap(),
        baseline.read_root_at_transcript_boundary().unwrap(),
        "{} eager root",
        case.name
    );
    assert_eq!(
        candidate.retained_layers_bottom_up().len(),
        baseline.retained_layers_bottom_up().len()
    );
    for (index, (&candidate_layer, &baseline_layer)) in candidate
        .retained_layers_bottom_up()
        .iter()
        .zip(baseline.retained_layers_bottom_up())
        .enumerate()
    {
        assert_eq!(
            read_hashes(&candidate_arena, candidate_layer),
            read_hashes(&baseline_arena, baseline_layer),
            "{} eager retained layer {index}",
            case.name
        );
    }

    let capture = baseline_arena.context().capture().unwrap();
    baseline.launch().unwrap();
    let baseline_graph = capture.finish().unwrap();
    let capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    assert_eq!(
        baseline_graph.kernel_nodes() - candidate_graph.kernel_nodes(),
        1,
        "{} captured kernel savings",
        case.name
    );
    baseline_graph.launch(baseline_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    assert_eq!(
        assert_direct_outputs(
            &base,
            &first_oracle.retained_evaluations,
            &candidate_arena,
            candidate.leaf_hashes(),
            candidate.retained_evaluations(),
        ),
        eager_candidate,
        "{} replay",
        case.name
    );

    if measure {
        const WARMUPS: usize = 8;
        const ITERATIONS: usize = 40;
        macro_rules! sample {
            ($arena:expr, $graph:expr) => {{
                let context = $arena.context();
                assert!(context.begin_timing().unwrap() >= 1);
                $graph.launch(context).unwrap();
                context.mark_timing().unwrap();
                context.sync().unwrap();
                f64::from(context.elapsed_timing_ms(1).unwrap()[0])
            }};
        }
        for iteration in 0..WARMUPS {
            if iteration % 2 == 0 {
                let _ = sample!(baseline_arena, baseline_graph);
                let _ = sample!(candidate_arena, candidate_graph);
            } else {
                let _ = sample!(candidate_arena, candidate_graph);
                let _ = sample!(baseline_arena, baseline_graph);
            }
        }
        let mut baseline_ms = Vec::with_capacity(ITERATIONS);
        let mut candidate_ms = Vec::with_capacity(ITERATIONS);
        for iteration in 0..ITERATIONS {
            if iteration % 2 == 0 {
                baseline_ms.push(sample!(baseline_arena, baseline_graph));
                candidate_ms.push(sample!(candidate_arena, candidate_graph));
            } else {
                candidate_ms.push(sample!(candidate_arena, candidate_graph));
                baseline_ms.push(sample!(baseline_arena, baseline_graph));
            }
        }
        let median = |samples: &[f64]| {
            let mut sorted = samples.to_vec();
            sorted.sort_by(f64::total_cmp);
            sorted[sorted.len() / 2]
        };
        let baseline_median = median(&baseline_ms);
        let candidate_median = median(&candidate_ms);
        println!(
            "DIRECT_TERMINAL_ABBA_JSON={{\"case\":\"{}\",\"warmups\":{},\
             \"iterations\":{},\"baseline_median_ms\":{},\"candidate_median_ms\":{},\
             \"candidate_speedup\":{},\"baseline_ms\":{:?},\"candidate_ms\":{:?}}}",
            case.name,
            WARMUPS,
            ITERATIONS,
            baseline_median,
            candidate_median,
            baseline_median / candidate_median,
            baseline_ms,
            candidate_ms,
        );
    }

    let second_sources = coefficients(&base, 0xc001_cafe);
    for (column, words) in baseline_columns.iter().zip(&second_sources) {
        upload(&baseline_arena, column.source_evaluations, words);
    }
    for (column, words) in candidate_columns.iter().zip(&second_sources) {
        upload(&candidate_arena, column.source_evaluations, words);
    }
    baseline_graph.launch(baseline_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let second_oracle = direct.oracle(&second_sources).unwrap();
    let mutated_baseline = assert_direct_outputs(
        &base,
        &second_oracle.retained_evaluations,
        &baseline_arena,
        baseline.leaf_hashes(),
        baseline.retained_evaluations(),
    );
    let mutated_candidate = assert_direct_outputs(
        &base,
        &second_oracle.retained_evaluations,
        &candidate_arena,
        candidate.leaf_hashes(),
        candidate.retained_evaluations(),
    );
    assert_eq!(
        mutated_candidate, mutated_baseline,
        "{} mutation",
        case.name
    );
    assert_ne!(
        mutated_candidate, eager_candidate,
        "{} stale replay",
        case.name
    );
    assert_eq!(
        candidate.read_root_at_transcript_boundary().unwrap(),
        baseline.read_root_at_transcript_boundary().unwrap(),
        "{} mutated root",
        case.name
    );
}

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires native CUDA")]
fn direct_compact_terminal_log13_c16_matches_materialized_eager_capture_and_mutation() {
    run_direct_terminal(
        Case {
            name: "direct-terminal-log13-c16",
            lifting_log_size: 13,
            groups: vec![vec![12; 16]],
            transitions: 0,
        },
        16,
        1,
        0,
        false,
    );
}

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires native CUDA")]
fn direct_compact_terminal_stage8_two_tiles_matches_materialized() {
    run_direct_terminal(
        Case {
            name: "direct-terminal-log14-c32",
            lifting_log_size: 14,
            groups: vec![vec![13; 32]],
            transitions: 0,
        },
        32,
        2,
        0,
        false,
    );
}

#[test]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires native CUDA")]
fn direct_compact_terminal_nonempty_tail_matches_materialized() {
    run_direct_terminal(
        Case {
            name: "direct-terminal-nonempty-tail",
            lifting_log_size: 13,
            groups: vec![vec![4; 5], vec![12; 16]],
            transitions: 1,
        },
        16,
        1,
        1,
        false,
    );
}

#[test]
#[ignore = "diagnostic A40 ABBA; run explicitly"]
#[cfg_attr(not(stwo_cuda_link), ignore = "requires native CUDA")]
fn direct_compact_terminal_log16_c16_abba() {
    run_direct_terminal(
        Case {
            name: "direct-terminal-log16-c16",
            lifting_log_size: 16,
            groups: vec![vec![15; 16]],
            transitions: 0,
        },
        16,
        1,
        0,
        true,
    );
}
