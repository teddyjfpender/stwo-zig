//! Exact-shape native admission for the Composition split and compact commit.
//!
//! The reference materializes the production-predecessor semantics through the
//! qualified stage-fused exact-alias B2N: full coefficients, eight half copies,
//! ordinary compact LDE, leaf hashing, and Merkle. The candidate uses the
//! qualified fused split at log 24 and 25, followed directly by compact hashing
//! of its evaluations.
//! gpu-lab-cohesion-review: one native gate must bind both graph lifetimes and compare every
//! shared semantic boundary. Run on a >=16 GiB CUDA device with:
//!
//! ```text
//! cargo test -p stwo-backend-cuda --test composition_split_commit_native \
//!   --release -- --ignored --nocapture
//! ```

#![cfg(stwo_cuda_link)]

use std::time::Instant;

use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo_backend_cuda::{
    gpu_memory_info, ArenaSlice, ArenaSlotId, CommitCoefficientColumn, CommitProgram,
    CompactDomainOperation, CompactDomainProgram, CompositionSplitColumns,
    CompositionSplitLaunchMode, CompositionSplitPointerSlots, CompositionSplitProgram, DeviceArena,
    DomainCooperativeProgram, PreparedCompactDomainCommitGraph, PreparedCompositionSplitGraph,
    PreparedPrecomputedCompactDomainCommitGraph, ProgressiveCommitWorkspaceSlots,
    COMPOSITION_RETAINED_COLUMNS, COMPOSITION_SOURCE_COORDINATES,
};

#[path = "support/composition_split_commit_layout.rs"]
mod composition_split_commit_layout;
use composition_split_commit_layout::{build_arena, programs, workspace_slots};

const MODULUS: u32 = 0x7fff_ffff;
const GUARD_WORD: u32 = 0xdead_beef;
const GUARD_WORDS: usize = 64;
const HOST_CHUNK_WORDS: usize = 1 << 20;

const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(1);
const FORWARD_TWIDDLES: ArenaSlotId = ArenaSlotId(2);
const BASELINE_SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(3);
const CANDIDATE_SOURCE_POINTERS: ArenaSlotId = ArenaSlotId(4);
const CANDIDATE_OUTPUT_POINTERS: ArenaSlotId = ArenaSlotId(5);
const BASELINE_SOURCE_BASE: u32 = 100;
const CANDIDATE_SOURCE_BASE: u32 = 110;
const BASELINE_COEFFICIENT_BASE: u32 = 200;
const BASELINE_OUTPUT_BASE: u32 = 220;
const CANDIDATE_OUTPUT_BASE: u32 = 240;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WordDigest {
    sum: u64,
    mixed: u64,
}

impl WordDigest {
    fn absorb(&mut self, word: u32, index: usize) {
        let keyed = u64::from(word) ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        self.sum = self.sum.wrapping_add(keyed);
        self.mixed = self
            .mixed
            .rotate_left(9)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ keyed;
    }
}

struct PreparedCase<'a> {
    baseline: PreparedCompactDomainCommitGraph<'a>,
    candidate_split: PreparedCompositionSplitGraph<'a>,
    candidate: PreparedPrecomputedCompactDomainCommitGraph<'a>,
    expected_baseline_kernel_nodes: u64,
    expected_candidate_kernel_nodes: u64,
}

#[derive(Debug)]
struct CaseReceipt {
    log_size: u32,
    candidate_launch_mode: CompositionSplitLaunchMode,
    arena_bytes: usize,
    baseline_graph_kernel_nodes: u64,
    candidate_graph_kernel_nodes: u64,
    expected_baseline_kernel_nodes: u64,
    expected_candidate_kernel_nodes: u64,
    modeled_current_logical_bytes: u64,
    modeled_candidate_logical_bytes: u64,
    expected_captured_d2d_nodes: u32,
    captured_d2d_bytes: u64,
    baseline_leaf_api_calls: usize,
    candidate_leaf_api_calls: usize,
    merkle_api_calls: usize,
    eager_digest: WordDigest,
    capture_digest: WordDigest,
    mutation_digest: WordDigest,
    elapsed_ms: u128,
}

fn ids<const N: usize>(base: u32) -> [ArenaSlotId; N] {
    std::array::from_fn(|index| ArenaSlotId(base + index as u32))
}

fn exact(arena: &DeviceArena, id: ArenaSlotId, words: usize) -> ArenaSlice {
    arena.bind(id).unwrap().checked_subslice(0, words).unwrap()
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

fn upload_twiddles(arena: &DeviceArena, log_size: u32) {
    let twiddles =
        CpuBackend::precompute_twiddles(CanonicCoset::new(log_size).circle_domain().half_coset);
    let inverse = twiddles
        .itwiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    upload(arena, arena.bind(INVERSE_TWIDDLES).unwrap(), &inverse);
    let forward = twiddles
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    upload(arena, arena.bind(FORWARD_TWIDDLES).unwrap(), &forward);
    arena.context().sync().unwrap();
}

fn upload_baseline_source_pointers(arena: &DeviceArena, rows: usize) {
    let pointers = ids::<COMPOSITION_SOURCE_COORDINATES>(BASELINE_SOURCE_BASE)
        .map(|id| exact(arena, id, rows).as_u32_ptr() as usize);
    let destination = arena.bind(BASELINE_SOURCE_POINTERS).unwrap();
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                destination.as_void_ptr(),
                pointers.as_ptr().cast(),
                core::mem::size_of_val(&pointers),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
}

fn pattern_word(seed: u64, coordinate: usize, row: usize) -> u32 {
    let mut value = seed
        ^ (coordinate as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (row as u64).wrapping_mul(0xd6e8_feb8_6659_fd93);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    ((value ^ (value >> 31)) % u64::from(MODULUS)) as u32
}

fn data_slots() -> impl Iterator<Item = ArenaSlotId> {
    ids::<COMPOSITION_SOURCE_COORDINATES>(BASELINE_SOURCE_BASE)
        .into_iter()
        .chain(ids::<COMPOSITION_SOURCE_COORDINATES>(CANDIDATE_SOURCE_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(
            BASELINE_COEFFICIENT_BASE,
        ))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(BASELINE_OUTPUT_BASE))
        .chain(ids::<COMPOSITION_RETAINED_COLUMNS>(CANDIDATE_OUTPUT_BASE))
}

fn reset_inputs(arena: &DeviceArena, log_size: u32, seed: u64) {
    let rows = 1usize << log_size;
    for id in data_slots() {
        let slot = arena.bind(id).unwrap();
        unsafe {
            arena
                .context()
                .fill_u32_async(slot.as_u32_ptr(), GUARD_WORD, slot.len_words())
                .unwrap();
        }
    }
    arena.context().sync().unwrap();
    let mut host = vec![0u32; HOST_CHUNK_WORDS.min(rows)];
    for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
        let baseline = exact(
            arena,
            ArenaSlotId(BASELINE_SOURCE_BASE + coordinate as u32),
            rows,
        );
        let candidate = exact(
            arena,
            ArenaSlotId(CANDIDATE_SOURCE_BASE + coordinate as u32),
            rows,
        );
        for first in (0..rows).step_by(HOST_CHUNK_WORDS) {
            let count = HOST_CHUNK_WORDS.min(rows - first);
            for (local, word) in host[..count].iter_mut().enumerate() {
                *word = pattern_word(seed, coordinate, first + local);
            }
            for destination in [baseline, candidate] {
                upload(
                    arena,
                    destination.checked_subslice(first, count).unwrap(),
                    &host[..count],
                );
            }
            arena.context().sync().unwrap();
        }
    }
}

fn retained_outputs(arena: &DeviceArena, base: u32, rows: usize) -> Vec<Option<ArenaSlice>> {
    ids::<COMPOSITION_RETAINED_COLUMNS>(base)
        .into_iter()
        .map(|id| Some(exact(arena, id, rows)))
        .collect()
}

fn prepare<'a>(
    arena: &'a DeviceArena,
    log_size: u32,
    base: &CommitProgram,
    compact: &CompactDomainProgram,
    domain: &DomainCooperativeProgram,
    split: CompositionSplitProgram,
    baseline_workspace: ProgressiveCommitWorkspaceSlots,
    candidate_workspace: ProgressiveCommitWorkspaceSlots,
) -> PreparedCase<'a> {
    let rows = 1usize << log_size;
    let half = rows / 2;
    let baseline_coefficients = ids::<COMPOSITION_RETAINED_COLUMNS>(BASELINE_COEFFICIENT_BASE)
        .into_iter()
        .map(|id| CommitCoefficientColumn {
            coefficients: exact(arena, id, half),
            log_size: log_size - 1,
        })
        .collect::<Vec<_>>();
    let baseline_outputs = retained_outputs(arena, BASELINE_OUTPUT_BASE, rows);
    let candidate_outputs = retained_outputs(arena, CANDIDATE_OUTPUT_BASE, rows);
    let baseline = compact
        .bind_prepared(
            arena,
            base,
            domain,
            &baseline_workspace,
            &baseline_coefficients,
            &baseline_outputs,
            arena.bind(FORWARD_TWIDDLES).unwrap(),
        )
        .unwrap();
    assert!(matches!(log_size, 24 | 25));
    let candidate_launch_mode = CompositionSplitLaunchMode::FusedFirstForward;
    let candidate_split = PreparedCompositionSplitGraph::prepare(
        arena,
        split,
        candidate_launch_mode,
        CompositionSplitPointerSlots {
            source_pointers: CANDIDATE_SOURCE_POINTERS,
            retained_pointers: CANDIDATE_OUTPUT_POINTERS,
        },
        CompositionSplitColumns {
            source_evaluations: ids::<COMPOSITION_SOURCE_COORDINATES>(CANDIDATE_SOURCE_BASE)
                .map(|id| exact(arena, id, rows)),
            retained_evaluations: ids::<COMPOSITION_RETAINED_COLUMNS>(CANDIDATE_OUTPUT_BASE)
                .map(|id| exact(arena, id, rows)),
        },
        arena.bind(INVERSE_TWIDDLES).unwrap(),
        arena.bind(FORWARD_TWIDDLES).unwrap(),
    )
    .unwrap();
    let candidate = compact
        .bind_prepared_evaluations(
            arena,
            base,
            domain,
            &candidate_workspace,
            &candidate_outputs,
        )
        .unwrap();
    let merkle_nodes = compact
        .merkle_suffix()
        .iter()
        .map(|step| u64::from(step.traffic.kernel_launches))
        .sum::<u64>();
    let baseline_commit_nodes = compact
        .steps()
        .iter()
        .map(|step| u64::from(step.traffic.kernel_launches))
        .sum::<u64>()
        + merkle_nodes;
    let candidate_commit_nodes = compact
        .steps()
        .iter()
        .filter(|step| !matches!(step.operation, CompactDomainOperation::LdeBatch { .. }))
        .map(|step| u64::from(step.traffic.kernel_launches))
        .sum::<u64>()
        + merkle_nodes;
    let expected_baseline_kernel_nodes =
        u64::from(split.schedule().inverse_intervals) + baseline_commit_nodes;
    let candidate_split_nodes = match candidate_launch_mode {
        CompositionSplitLaunchMode::TerminalFallback => {
            split.traffic().terminal_fallback_kernel_launches
        }
        CompositionSplitLaunchMode::FusedFirstForward => split.traffic().fused_kernel_launches,
    };
    let expected_candidate_kernel_nodes = u64::from(candidate_split_nodes) + candidate_commit_nodes;
    PreparedCase {
        baseline,
        candidate_split,
        candidate,
        expected_baseline_kernel_nodes,
        expected_candidate_kernel_nodes,
    }
}

fn launch_baseline(arena: &DeviceArena, log_size: u32) {
    let rows = 1usize << log_size;
    let half = rows / 2;
    let source_pointers = arena.bind(BASELINE_SOURCE_POINTERS).unwrap().as_u32_ptr();
    // Exact input/output aliases retain the full coefficient image while the
    // qualified interval topology matches the split traffic and node model.
    let code = unsafe {
        stwo_backend_cuda_kernels::raw::stwo_ntt_b2n_columns_out_of_place_on(
            source_pointers.cast::<*const u32>(),
            source_pointers.cast::<*mut u32>(),
            log_size,
            COMPOSITION_SOURCE_COORDINATES as u32,
            arena.bind(INVERSE_TWIDDLES).unwrap().as_u32_ptr(),
            half as u32,
            half as u32,
            arena.context().stream_raw().as_ptr(),
        )
    };
    assert_eq!(code, 0, "baseline B2N status");
    for half_index in 0..2 {
        for coordinate in 0..COMPOSITION_SOURCE_COORDINATES {
            let source = exact(
                arena,
                ArenaSlotId(BASELINE_SOURCE_BASE + coordinate as u32),
                rows,
            )
            .checked_subslice(half_index * half, half)
            .unwrap();
            let destination = exact(
                arena,
                ArenaSlotId(
                    BASELINE_COEFFICIENT_BASE
                        + (half_index * COMPOSITION_SOURCE_COORDINATES + coordinate) as u32,
                ),
                half,
            );
            unsafe {
                arena
                    .context()
                    .memcpy_d2d_async(
                        destination.as_void_ptr(),
                        source.as_void_ptr().cast_const(),
                        half * core::mem::size_of::<u32>(),
                    )
                    .unwrap();
            }
        }
    }
}

fn launch_baseline_commit(arena: &DeviceArena, log_size: u32, prepared: &PreparedCase<'_>) {
    launch_baseline(arena, log_size);
    prepared.baseline.launch().unwrap();
}

fn launch_candidate(prepared: &PreparedCase<'_>) {
    prepared.candidate_split.launch().unwrap();
    prepared.candidate.launch().unwrap();
}

fn launch_all(arena: &DeviceArena, log_size: u32, prepared: &PreparedCase<'_>) {
    launch_baseline_commit(arena, log_size, prepared);
    launch_candidate(prepared);
}

fn read_words(arena: &DeviceArena, source: ArenaSlice, output: &mut [u32]) {
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                output.as_mut_ptr().cast(),
                source.as_void_ptr().cast_const(),
                core::mem::size_of_val(output),
            )
            .unwrap();
    }
}

fn compare_pair(
    arena: &DeviceArena,
    left: ArenaSlice,
    right: ArenaSlice,
    label: &str,
    digest: &mut WordDigest,
    digest_base: usize,
    canonical: bool,
) {
    assert_eq!(left.len_words(), right.len_words(), "{label} length");
    let mut left_host = vec![0u32; HOST_CHUNK_WORDS.min(left.len_words())];
    let mut right_host = vec![0u32; left_host.len()];
    for first in (0..left.len_words()).step_by(HOST_CHUNK_WORDS) {
        let count = HOST_CHUNK_WORDS.min(left.len_words() - first);
        read_words(
            arena,
            left.checked_subslice(first, count).unwrap(),
            &mut left_host[..count],
        );
        read_words(
            arena,
            right.checked_subslice(first, count).unwrap(),
            &mut right_host[..count],
        );
        arena.context().sync().unwrap();
        for local in 0..count {
            let index = first + local;
            assert_eq!(left_host[local], right_host[local], "{label} word {index}");
            if canonical {
                assert!(left_host[local] < MODULUS, "{label} noncanonical {index}");
            }
            digest.absorb(left_host[local], digest_base + index);
        }
    }
}

fn verify(arena: &DeviceArena, log_size: u32, prepared: &PreparedCase<'_>) -> WordDigest {
    let rows = 1usize << log_size;
    let mut digest = WordDigest { sum: 0, mixed: 0 };
    // Retained evaluations are the first common semantic boundary. The
    // predecessor materializes terminal coefficients in its source and copy
    // slabs; the fused candidate intentionally keeps them in registers/shared
    // memory, so those internal postimages are not equivalent representations.
    for column in 0..COMPOSITION_RETAINED_COLUMNS {
        compare_pair(
            arena,
            exact(
                arena,
                ArenaSlotId(BASELINE_OUTPUT_BASE + column as u32),
                rows,
            ),
            exact(
                arena,
                ArenaSlotId(CANDIDATE_OUTPUT_BASE + column as u32),
                rows,
            ),
            &format!("evaluation {column}"),
            &mut digest,
            (12 + column) * rows,
            true,
        );
    }
    compare_pair(
        arena,
        prepared.baseline.leaf_hashes(),
        prepared.candidate.leaf_hashes(),
        "leaf hashes",
        &mut digest,
        20 * rows,
        false,
    );
    assert_eq!(
        prepared.baseline.retained_layers_bottom_up().len(),
        prepared.candidate.retained_layers_bottom_up().len()
    );
    for (layer, (&left, &right)) in prepared
        .baseline
        .retained_layers_bottom_up()
        .iter()
        .zip(prepared.candidate.retained_layers_bottom_up())
        .enumerate()
    {
        compare_pair(
            arena,
            left,
            right,
            &format!("Merkle layer {layer}"),
            &mut digest,
            (21 + layer) * rows,
            false,
        );
    }
    compare_pair(
        arena,
        prepared.baseline.root_slice(),
        prepared.candidate.root_slice(),
        "root",
        &mut digest,
        30 * rows,
        false,
    );
    assert_eq!(
        prepared
            .baseline
            .read_root_at_transcript_boundary()
            .unwrap(),
        prepared
            .candidate
            .read_root_at_transcript_boundary()
            .unwrap()
    );
    assert_guards(arena, rows, rows / 2);
    digest
}

fn assert_guards(arena: &DeviceArena, rows: usize, half: usize) {
    let mut host = [0u32; GUARD_WORDS];
    for id in data_slots() {
        let data_words = if (BASELINE_COEFFICIENT_BASE
            ..BASELINE_COEFFICIENT_BASE + COMPOSITION_RETAINED_COLUMNS as u32)
            .contains(&id.0)
        {
            half
        } else {
            rows
        };
        read_words(
            arena,
            arena
                .bind(id)
                .unwrap()
                .checked_subslice(data_words, GUARD_WORDS)
                .unwrap(),
            &mut host,
        );
        arena.context().sync().unwrap();
        assert!(host.iter().all(|&word| word == GUARD_WORD), "guard {id:?}");
    }
}

fn run_case(log_size: u32) -> CaseReceipt {
    let started = Instant::now();
    let (base, domain, compact) = programs(log_size);
    let split = CompositionSplitProgram::compile(log_size).unwrap();
    let baseline_workspace = workspace_slots(base.requirements(), 1_000);
    let candidate_workspace = workspace_slots(base.requirements(), 2_000);
    let arena = build_arena(
        log_size,
        &base,
        &domain,
        &compact,
        split,
        &baseline_workspace,
        &candidate_workspace,
    );
    let arena_bytes = arena.layout().total_words() * core::mem::size_of::<u32>();
    upload_twiddles(&arena, log_size);
    upload_baseline_source_pointers(&arena, 1usize << log_size);
    let prepared = prepare(
        &arena,
        log_size,
        &base,
        &compact,
        &domain,
        split,
        baseline_workspace,
        candidate_workspace,
    );
    let baseline_leaf_api_calls = prepared.baseline.leaf_launch_sequence().len();
    let candidate_leaf_api_calls = prepared.candidate.leaf_launch_sequence().len();
    let merkle_api_calls = prepared.baseline.merkle_launch_sequence().len();
    assert_eq!(baseline_leaf_api_calls, candidate_leaf_api_calls + 1);
    assert_eq!(
        merkle_api_calls,
        prepared.candidate.merkle_launch_sequence().len()
    );

    reset_inputs(&arena, log_size, 0x0123_4567_89ab_cdef);
    launch_all(&arena, log_size, &prepared);
    arena.context().sync().unwrap();
    let eager_digest = verify(&arena, log_size, &prepared);

    reset_inputs(&arena, log_size, 0x89ab_cdef_0123_4567);
    let telemetry_before = arena.context().telemetry();
    let baseline_capture = arena.context().capture().unwrap();
    launch_baseline_commit(&arena, log_size, &prepared);
    let baseline_graph = baseline_capture.finish().unwrap();
    let telemetry_after = arena.context().telemetry();
    let candidate_capture = arena.context().capture().unwrap();
    launch_candidate(&prepared);
    let candidate_graph = candidate_capture.finish().unwrap();
    assert_eq!(
        baseline_graph.kernel_nodes(),
        prepared.expected_baseline_kernel_nodes
    );
    assert_eq!(
        candidate_graph.kernel_nodes(),
        prepared.expected_candidate_kernel_nodes
    );
    let observed_kernel_nodes_saved = baseline_graph
        .kernel_nodes()
        .checked_sub(candidate_graph.kernel_nodes())
        .expect("candidate graph added kernel nodes");
    let candidate_split_nodes = match prepared.candidate_split.mode() {
        CompositionSplitLaunchMode::TerminalFallback => {
            split.traffic().terminal_fallback_kernel_launches
        }
        CompositionSplitLaunchMode::FusedFirstForward => split.traffic().fused_kernel_launches,
    };
    assert_eq!(
        observed_kernel_nodes_saved,
        u64::from(split.traffic().current_kernel_launches - candidate_split_nodes)
    );
    let captured_d2d_bytes = telemetry_after.d2d_bytes - telemetry_before.d2d_bytes;
    assert_eq!(
        captured_d2d_bytes,
        split.traffic().source_image_bytes,
        "captured coefficient-half traffic"
    );
    baseline_graph.launch(arena.context()).unwrap();
    candidate_graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let capture_digest = verify(&arena, log_size, &prepared);

    reset_inputs(&arena, log_size, 0xfedc_ba98_7654_3210);
    baseline_graph.launch(arena.context()).unwrap();
    candidate_graph.launch(arena.context()).unwrap();
    arena.context().sync().unwrap();
    let mutation_digest = verify(&arena, log_size, &prepared);
    assert_ne!(eager_digest, capture_digest);
    assert_ne!(capture_digest, mutation_digest);

    CaseReceipt {
        log_size,
        candidate_launch_mode: prepared.candidate_split.mode(),
        arena_bytes,
        baseline_graph_kernel_nodes: baseline_graph.kernel_nodes(),
        candidate_graph_kernel_nodes: candidate_graph.kernel_nodes(),
        expected_baseline_kernel_nodes: prepared.expected_baseline_kernel_nodes,
        expected_candidate_kernel_nodes: prepared.expected_candidate_kernel_nodes,
        modeled_current_logical_bytes: split.traffic().current_logical_bytes,
        modeled_candidate_logical_bytes: match prepared.candidate_split.mode() {
            CompositionSplitLaunchMode::TerminalFallback => {
                split.traffic().terminal_fallback_logical_bytes
            }
            CompositionSplitLaunchMode::FusedFirstForward => split.traffic().fused_logical_bytes,
        },
        expected_captured_d2d_nodes: split.traffic().current_d2d_nodes,
        captured_d2d_bytes,
        baseline_leaf_api_calls,
        candidate_leaf_api_calls,
        merkle_api_calls,
        eager_digest,
        capture_digest,
        mutation_digest,
        elapsed_ms: started.elapsed().as_millis(),
    }
}

fn requested_logs() -> Vec<u32> {
    let mut logs = std::env::var("STWO_COMPOSITION_COMMIT_LOGS")
        .unwrap_or_else(|_| "24,25".to_owned())
        .split(',')
        .map(|value| value.trim().parse::<u32>().unwrap())
        .collect::<Vec<_>>();
    logs.sort_unstable();
    logs.dedup();
    assert!(!logs.is_empty());
    assert!(logs.iter().all(|log| matches!(log, 24 | 25)));
    logs
}

#[test]
#[ignore = "requires exact log24/log25 native CUDA execution"]
fn fused_split_precomputed_commit_matches_legacy_pipeline_exactly() {
    assert!(stwo_backend_cuda_kernels::CUDA_KERNELS_BUILT);
    let memory_before = gpu_memory_info();
    let receipts = requested_logs()
        .into_iter()
        .map(run_case)
        .collect::<Vec<_>>();
    let memory_after = gpu_memory_info();
    let cases = receipts
        .iter()
        .map(|receipt| {
            serde_json::json!({
                "log_size": receipt.log_size,
                "candidate_launch_mode": format!("{:?}", receipt.candidate_launch_mode),
                "arena_bytes": receipt.arena_bytes,
                "baseline_graph_kernel_nodes": receipt.baseline_graph_kernel_nodes,
                "candidate_graph_kernel_nodes": receipt.candidate_graph_kernel_nodes,
                "expected_baseline_kernel_nodes": receipt.expected_baseline_kernel_nodes,
                "expected_candidate_kernel_nodes": receipt.expected_candidate_kernel_nodes,
                "observed_kernel_nodes_saved": receipt.baseline_graph_kernel_nodes - receipt.candidate_graph_kernel_nodes,
                "modeled_current_logical_bytes": receipt.modeled_current_logical_bytes,
                "modeled_candidate_logical_bytes": receipt.modeled_candidate_logical_bytes,
                "modeled_logical_bytes_saved": receipt.modeled_current_logical_bytes - receipt.modeled_candidate_logical_bytes,
                "expected_captured_d2d_nodes": receipt.expected_captured_d2d_nodes,
                "captured_d2d_bytes": receipt.captured_d2d_bytes,
                "baseline_leaf_api_calls": receipt.baseline_leaf_api_calls,
                "candidate_leaf_api_calls": receipt.candidate_leaf_api_calls,
                "merkle_api_calls": receipt.merkle_api_calls,
                "eager_digest": [receipt.eager_digest.sum, receipt.eager_digest.mixed],
                "capture_digest": [receipt.capture_digest.sum, receipt.capture_digest.mixed],
                "mutation_digest": [receipt.mutation_digest.sum, receipt.mutation_digest.mixed],
                "elapsed_ms": receipt.elapsed_ms,
            })
        })
        .collect::<Vec<_>>();
    eprintln!(
        "STWO_COMPOSITION_SPLIT_COMMIT_NATIVE_RECEIPT_JSON={}",
        serde_json::json!({
            "schema": "stwo.composition-split-commit-native.v2",
            "passed": true,
            "baseline": "b2n-plus-eight-d2d-plus-ordinary-compact-commit",
            "candidate": "qualified-split-plus-precomputed-compact-commit",
            "semantic_equivalence_boundary": "retained-evaluations",
            "candidate_terminal_coefficients_materialized": false,
            "log24_candidate_launch_mode": "FusedFirstForward",
            "log25_candidate_launch_mode": "FusedFirstForward",
            "retained_evaluations_equal": true,
            "leaf_hashes_equal": true,
            "retained_merkle_layers_equal": true,
            "roots_equal": true,
            "guards_preserved": true,
            "eager": true,
            "capture_replay": true,
            "mutated_replay": true,
            "host_chunk_bytes": HOST_CHUNK_WORDS * core::mem::size_of::<u32>(),
            "memory_before": memory_before,
            "memory_after": memory_after,
            "cases": cases,
        })
    );
}
