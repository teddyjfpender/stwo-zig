use std::collections::BTreeMap;

use stwo::core::fields::m31::BaseField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::{CircleCoefficients, PolyOps};
use stwo_backend_cuda::{
    ArenaSlotId, CommitArenaSlotRequirement, CommitCoefficientColumn, CommitProgram,
    CommitWorkspaceConfig, DeviceArena, DomainCooperativeProgram, MerkleFromLeavesSlots,
    PreparedProgressiveCommitGraph, ProgressiveBatchSlots, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry, ProgressiveCommitWorkspaceRequirements,
    ProgressiveCommitWorkspaceSlots, ProgressiveLeafLaunchKind, ProgressiveLeafWorkspaceSlots,
    ProgressiveNttLeafFusionMode,
};
use stwo_backend_cuda_kernels::raw::{
    stwo_blake2s_progressive_absorb_on, stwo_blake2s_progressive_absorb_quad_on,
    stwo_blake2s_progressive_finalize_on, stwo_blake2s_progressive_init_on,
    ProgressiveBlake2sState,
};

use super::replacement_stage4_common::{
    arena, fill, hash_hashes, hash_words, read_hashes, read_words, upload_usizes, upload_words,
    FixtureReceipt, SlotRequest,
};

const RAW_POINTERS: ArenaSlotId = ArenaSlotId(1_000);
const RAW_COLUMN_BASE: u32 = 1_010;
const RAW_LEGACY_STATE: ArenaSlotId = ArenaSlotId(1_100);
const RAW_CANDIDATE_STATE: ArenaSlotId = ArenaSlotId(1_101);
const RAW_LEGACY_HASH: ArenaSlotId = ArenaSlotId(1_102);
const RAW_CANDIDATE_HASH: ArenaSlotId = ArenaSlotId(1_103);
const RAW_GUARD: ArenaSlotId = ArenaSlotId(1_104);
pub(super) const TWIDDLES: ArenaSlotId = ArenaSlotId(2_000);
const SOURCE_BASE: u32 = 2_100;
const OUTPUT_BASE: u32 = 2_200;
pub(super) const GUARD: ArenaSlotId = ArenaSlotId(2_300);
const GUARD_WORDS: usize = 64;
const ROWS: usize = 8;
pub(super) const COLUMNS: usize = 33;

pub fn run() -> FixtureReceipt {
    let (raw_bytes, raw_hashes) = raw_prefix_boundaries();
    let (integrated_bytes, integrated_hashes) = integrated_commit();
    let mut hashes = BTreeMap::new();
    hashes.extend(raw_hashes);
    hashes.extend(integrated_hashes);
    let checks = [
        ("raw_prefix_boundary_identity", true),
        ("eager_reference", true),
        ("legacy_candidate_byte_identity", true),
        ("captured_graph_mutation", true),
        ("source_preservation", true),
        ("guard_preservation", true),
    ]
    .into_iter()
    .map(|(name, passed)| (name.to_owned(), passed))
    .collect();
    FixtureReceipt {
        name: "mode-a-domain-cooperative-commit",
        production_apis: vec![
            "CommitProgram::bind",
            "DomainCooperativeProgram::compile_mode_a",
            "DomainCooperativeProgram::bind",
        ],
        cases: 9,
        arena_bytes: raw_bytes + integrated_bytes,
        checks,
        hashes,
    }
}

fn raw_prefix_boundaries() -> (usize, BTreeMap<String, String>) {
    let state_words = core::mem::size_of::<ProgressiveBlake2sState>() / 4;
    let pointer_words = COLUMNS * core::mem::size_of::<usize>().div_ceil(4);
    let mut requests = vec![
        request(
            RAW_POINTERS,
            pointer_words,
            core::mem::align_of::<usize>() / 4,
        ),
        request(RAW_LEGACY_STATE, ROWS * state_words, 8),
        request(RAW_CANDIDATE_STATE, ROWS * state_words, 8),
        request(RAW_LEGACY_HASH, ROWS * 8, 8),
        request(RAW_CANDIDATE_HASH, ROWS * 8, 8),
        request(RAW_GUARD, GUARD_WORDS, 8),
    ];
    requests.extend((0..COLUMNS).map(|column| request(raw_column_id(column), ROWS, 1)));
    let (arena, arena_bytes) = arena(requests);
    let columns = (0..COLUMNS)
        .map(|column| {
            (0..ROWS)
                .map(|row| {
                    (0x1234_5678u32
                        .wrapping_add((column as u32 + 1) * 104_729)
                        .wrapping_add(row as u32 * 7_919))
                        % 0x7fff_ffff
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    for (column, words) in columns.iter().enumerate() {
        upload_words(&arena, arena.bind(raw_column_id(column)).unwrap(), words);
    }
    let pointers = (0..COLUMNS)
        .map(|column| arena.bind(raw_column_id(column)).unwrap().as_u32_ptr() as usize)
        .collect::<Vec<_>>();
    upload_usizes(&arena, arena.bind(RAW_POINTERS).unwrap(), &pointers);
    fill(&arena, arena.bind(RAW_GUARD).unwrap(), 0x5a);
    arena.context().sync().unwrap();
    let pointer_table_before = read_words(&arena, arena.bind(RAW_POINTERS).unwrap(), pointer_words);

    let mut all_states = Vec::new();
    let mut all_hashes = Vec::new();
    for width in [1u32, 15, 16, 17, 31, 32, 33] {
        fill(&arena, arena.bind(RAW_LEGACY_STATE).unwrap(), 0xc3);
        fill(&arena, arena.bind(RAW_CANDIDATE_STATE).unwrap(), 0x3c);
        fill(&arena, arena.bind(RAW_LEGACY_HASH).unwrap(), 0xde);
        fill(&arena, arena.bind(RAW_CANDIDATE_HASH).unwrap(), 0xad);
        let stream = arena.context().stream_raw().as_ptr();
        let pointers = arena.bind(RAW_POINTERS).unwrap().as_u32_ptr().cast();
        let legacy_state = arena.bind(RAW_LEGACY_STATE).unwrap().as_u32_ptr().cast();
        let candidate_state = arena.bind(RAW_CANDIDATE_STATE).unwrap().as_u32_ptr().cast();
        unsafe {
            assert_eq!(
                stwo_blake2s_progressive_init_on(ROWS as u32, legacy_state, stream),
                0
            );
            assert_eq!(
                stwo_blake2s_progressive_absorb_on(
                    ROWS as u32,
                    width,
                    0,
                    pointers,
                    legacy_state,
                    stream,
                ),
                0
            );
            assert_eq!(
                stwo_blake2s_progressive_absorb_quad_on(
                    ROWS as u32,
                    width,
                    0,
                    pointers,
                    1,
                    candidate_state,
                    stream,
                ),
                0
            );
        }
        let legacy_state_words = read_words(
            &arena,
            arena.bind(RAW_LEGACY_STATE).unwrap(),
            ROWS * state_words,
        );
        let candidate_state_words = read_words(
            &arena,
            arena.bind(RAW_CANDIDATE_STATE).unwrap(),
            ROWS * state_words,
        );
        assert_eq!(candidate_state_words, legacy_state_words, "width={width}");
        unsafe {
            assert_eq!(
                stwo_blake2s_progressive_finalize_on(
                    ROWS as u32,
                    width,
                    legacy_state,
                    arena.bind(RAW_LEGACY_HASH).unwrap().as_u32_ptr().cast(),
                    stream,
                ),
                0
            );
            assert_eq!(
                stwo_blake2s_progressive_finalize_on(
                    ROWS as u32,
                    width,
                    candidate_state,
                    arena.bind(RAW_CANDIDATE_HASH).unwrap().as_u32_ptr().cast(),
                    stream,
                ),
                0
            );
        }
        let legacy_hashes = read_hashes(&arena, arena.bind(RAW_LEGACY_HASH).unwrap(), ROWS);
        let candidate_hashes = read_hashes(&arena, arena.bind(RAW_CANDIDATE_HASH).unwrap(), ROWS);
        assert_eq!(candidate_hashes, legacy_hashes, "finalized width={width}");
        all_states.extend(legacy_state_words);
        all_hashes.extend(legacy_hashes);
        assert_raw_preserved(&arena, &columns, &pointer_table_before);
    }
    let mut hashes = BTreeMap::new();
    hashes.insert("raw_prefix_states".to_owned(), hash_words(&all_states));
    hashes.insert("raw_prefix_hashes".to_owned(), hash_hashes(&all_hashes));
    (arena_bytes, hashes)
}

fn integrated_commit() -> (usize, BTreeMap<String, String>) {
    let base = integrated_program();
    let requirements = base.requirements();
    assert_eq!(requirements.leaves.plan.columns.len(), COLUMNS);
    assert!(requirements
        .leaves
        .plan
        .columns
        .iter()
        .all(|column| column.retained_evaluation));
    let slots = workspace_slots(requirements);
    let (legacy_arena, legacy_bytes) = commit_arena(requirements, &slots);
    let (candidate_arena, candidate_bytes) = commit_arena(requirements, &slots);
    let twiddle_words = required_twiddle_words(requirements);
    let first_coefficients = coefficient_set(requirements, 0x243f_6a88);
    let second_coefficients = coefficient_set(requirements, 0x85a3_08d3);
    for device in [&legacy_arena, &candidate_arena] {
        upload_words(device, device.bind(TWIDDLES).unwrap(), &twiddle_words);
        upload_coefficients(device, &first_coefficients);
        fill(device, device.bind(GUARD).unwrap(), 0x96);
        device.context().sync().unwrap();
    }
    let legacy_columns = coefficient_columns(&legacy_arena, requirements);
    let candidate_columns = coefficient_columns(&candidate_arena, requirements);
    let legacy_outputs = retained_outputs(&legacy_arena, requirements);
    let candidate_outputs = retained_outputs(&candidate_arena, requirements);
    let legacy = base
        .bind(
            &legacy_arena,
            &slots,
            &legacy_columns,
            &legacy_outputs,
            legacy_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();
    let cooperative = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let candidate = cooperative
        .bind(
            &candidate_arena,
            &base,
            &slots,
            &candidate_columns,
            &candidate_outputs,
            candidate_arena.bind(TWIDDLES).unwrap(),
        )
        .unwrap();
    let candidate_sequence = candidate.leaf_launch_sequence().collect::<Vec<_>>();
    assert!(candidate_sequence.iter().any(|launch| matches!(
        launch,
        ProgressiveLeafLaunchKind::DomainAbsorb {
            initializes_state: true,
            ..
        }
    )));
    assert!(!candidate_sequence.iter().any(|launch| matches!(
        launch,
        ProgressiveLeafLaunchKind::Init { .. } | ProgressiveLeafLaunchKind::Absorb { .. }
    )));

    let first_evaluations = evaluations(requirements, &first_coefficients);
    let first_oracle = base.oracle(&first_evaluations).unwrap();
    legacy.launch().unwrap();
    candidate.launch().unwrap();
    let eager_legacy = commit_snapshot(&legacy_arena, &legacy, &first_evaluations, &first_oracle);
    let eager_candidate = commit_snapshot(
        &candidate_arena,
        &candidate,
        &first_evaluations,
        &first_oracle,
    );
    assert_eq!(eager_candidate, eager_legacy);
    assert_commit_preserved(&legacy_arena, &first_coefficients);
    assert_commit_preserved(&candidate_arena, &first_coefficients);

    let legacy_capture = legacy_arena.context().capture().unwrap();
    legacy.launch().unwrap();
    let legacy_graph = legacy_capture.finish().unwrap();
    let candidate_capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = candidate_capture.finish().unwrap();
    for device in [&legacy_arena, &candidate_arena] {
        upload_coefficients(device, &second_coefficients);
    }
    legacy_graph.launch(legacy_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let second_evaluations = evaluations(requirements, &second_coefficients);
    let second_oracle = base.oracle(&second_evaluations).unwrap();
    let replay_legacy =
        commit_snapshot(&legacy_arena, &legacy, &second_evaluations, &second_oracle);
    let replay_candidate = commit_snapshot(
        &candidate_arena,
        &candidate,
        &second_evaluations,
        &second_oracle,
    );
    assert_eq!(replay_candidate, replay_legacy);
    assert_ne!(eager_candidate, replay_candidate);
    assert_commit_preserved(&legacy_arena, &second_coefficients);
    assert_commit_preserved(&candidate_arena, &second_coefficients);

    let mut hashes = BTreeMap::new();
    hashes.insert(
        "eager_root_and_retained".to_owned(),
        hash_words(&eager_candidate),
    );
    hashes.insert(
        "mutated_graph_root_and_retained".to_owned(),
        hash_words(&replay_candidate),
    );
    (legacy_bytes + candidate_bytes, hashes)
}

fn integrated_program() -> CommitProgram {
    CommitProgram::compile(
        CommitWorkspaceConfig {
            log_blowup_factor: 1,
            lifting_log_size: 7,
            unretained_bottom_layers: 4,
            max_fused_tail_levels: 2,
        },
        ProgressiveCommitGeometry {
            lifting_log_size: 7,
            log_blowup_factor: 1,
            groups: vec![
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![3; 15],
                    retain_evaluations: true,
                },
                ProgressiveCommitGroupGeometry {
                    coefficient_log_sizes: vec![4; 18],
                    retain_evaluations: true,
                },
            ],
        },
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap()
}

fn required_twiddle_words(requirements: &ProgressiveCommitWorkspaceRequirements) -> Vec<u32> {
    let full = forward_twiddle_words(requirements.leaves.plan.geometry.lifting_log_size);
    assert!(full.len() >= requirements.leaves.twiddle_words);
    full[full.len() - requirements.leaves.twiddle_words..].to_vec()
}

fn forward_twiddle_words(log_size: u32) -> Vec<u32> {
    CpuBackend::precompute_twiddles(CanonicCoset::new(log_size).circle_domain().half_coset)
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect()
}

#[test]
fn compact_mode_a_twiddles_match_largest_evaluation_tree() {
    let base = integrated_program();
    let requirements = base.requirements();
    let largest_evaluation_log = requirements
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| column.evaluation_log_size)
        .max()
        .unwrap();
    let compact = forward_twiddle_words(largest_evaluation_log);

    assert_eq!(requirements.leaves.twiddle_words, 16);
    assert_eq!(required_twiddle_words(requirements), compact);
}

pub(super) fn workspace_slots(
    requirements: &ProgressiveCommitWorkspaceRequirements,
) -> ProgressiveCommitWorkspaceSlots {
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

pub(super) fn commit_arena(
    requirements: &ProgressiveCommitWorkspaceRequirements,
    slots: &ProgressiveCommitWorkspaceSlots,
) -> (DeviceArena, usize) {
    let mut requests = requirements
        .arena_slot_requirements_in_place(slots)
        .unwrap()
        .into_iter()
        .map(commit_request)
        .collect::<Vec<_>>();
    requests.push(request(TWIDDLES, requirements.leaves.twiddle_words, 1));
    for column in &requirements.leaves.plan.columns {
        requests.push(request(
            source_id(column.canonical_index),
            1usize << column.coefficient_log_size,
            1,
        ));
        requests.push(request(
            output_id(column.canonical_index),
            1usize << column.evaluation_log_size,
            1,
        ));
    }
    requests.push(request(GUARD, GUARD_WORDS, 8));
    arena(requests)
}

pub(super) fn coefficient_set(
    requirements: &ProgressiveCommitWorkspaceRequirements,
    seed: u32,
) -> Vec<Vec<u32>> {
    requirements
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| {
            (0..1usize << column.coefficient_log_size)
                .map(|row| {
                    seed.wrapping_add((column.canonical_index as u32 + 1) * 104_729)
                        .wrapping_add(row as u32 * 7_919)
                        % 0x7fff_ffff
                })
                .collect()
        })
        .collect()
}

fn evaluations(
    requirements: &ProgressiveCommitWorkspaceRequirements,
    coefficients: &[Vec<u32>],
) -> Vec<Vec<u32>> {
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(requirements.leaves.plan.geometry.lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    requirements
        .leaves
        .plan
        .columns
        .iter()
        .zip(coefficients)
        .map(|(column, words)| {
            CircleCoefficients::<CpuBackend>::new(
                words
                    .iter()
                    .copied()
                    .map(BaseField::from_u32_unchecked)
                    .collect(),
            )
            .evaluate_with_twiddles(
                CanonicCoset::new(column.evaluation_log_size).circle_domain(),
                &twiddles,
            )
            .values
            .iter()
            .map(|value| value.0)
            .collect()
        })
        .collect()
}

pub(super) fn coefficient_columns(
    arena: &DeviceArena,
    requirements: &ProgressiveCommitWorkspaceRequirements,
) -> Vec<CommitCoefficientColumn> {
    requirements
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| CommitCoefficientColumn {
            coefficients: arena.bind(source_id(column.canonical_index)).unwrap(),
            log_size: column.coefficient_log_size,
        })
        .collect()
}

pub(super) fn retained_outputs(
    arena: &DeviceArena,
    requirements: &ProgressiveCommitWorkspaceRequirements,
) -> Vec<Option<stwo_backend_cuda::ArenaSlice>> {
    requirements
        .leaves
        .plan
        .columns
        .iter()
        .map(|column| Some(arena.bind(output_id(column.canonical_index)).unwrap()))
        .collect()
}

fn commit_snapshot(
    arena: &DeviceArena,
    prepared: &PreparedProgressiveCommitGraph<'_>,
    evaluations: &[Vec<u32>],
    oracle: &stwo_backend_cuda::CommitProgramOracle,
) -> Vec<u32> {
    let root = prepared.read_root_at_transcript_boundary().unwrap();
    assert_eq!(root, oracle.root);
    let mut result = bytes_as_words(&root.0);
    for (column, (destination, expected)) in prepared
        .retained_evaluations()
        .iter()
        .zip(evaluations)
        .enumerate()
    {
        let actual = read_words(arena, destination.unwrap(), expected.len());
        assert_eq!(actual, *expected, "retained evaluation column {column}");
        result.extend(actual);
    }
    assert_eq!(
        prepared.retained_layers_bottom_up().len(),
        oracle.retained_layers_bottom_up.len()
    );
    for (actual, expected) in prepared
        .retained_layers_bottom_up()
        .iter()
        .zip(&oracle.retained_layers_bottom_up)
    {
        let hashes = read_hashes(arena, *actual, expected.hashes.len());
        assert_eq!(
            hashes, expected.hashes,
            "retained Merkle log {}",
            expected.log_size
        );
        for hash in hashes {
            result.extend(bytes_as_words(&hash.0));
        }
    }
    result
}

pub(super) fn upload_coefficients(arena: &DeviceArena, coefficients: &[Vec<u32>]) {
    for (column, words) in coefficients.iter().enumerate() {
        upload_words(arena, arena.bind(source_id(column)).unwrap(), words);
    }
}

pub(super) fn assert_commit_preserved(arena: &DeviceArena, coefficients: &[Vec<u32>]) {
    for (column, expected) in coefficients.iter().enumerate() {
        assert_eq!(
            read_words(
                arena,
                arena.bind(source_id(column)).unwrap(),
                expected.len()
            ),
            *expected
        );
    }
    assert_eq!(
        read_words(arena, arena.bind(GUARD).unwrap(), GUARD_WORDS),
        vec![0x9696_9696; GUARD_WORDS]
    );
}

fn assert_raw_preserved(arena: &DeviceArena, columns: &[Vec<u32>], pointer_table: &[u32]) {
    for (column, expected) in columns.iter().enumerate() {
        assert_eq!(
            read_words(arena, arena.bind(raw_column_id(column)).unwrap(), ROWS),
            *expected
        );
    }
    assert_eq!(
        read_words(
            arena,
            arena.bind(RAW_POINTERS).unwrap(),
            pointer_table.len()
        ),
        pointer_table
    );
    assert_eq!(
        read_words(arena, arena.bind(RAW_GUARD).unwrap(), GUARD_WORDS),
        vec![0x5a5a_5a5a; GUARD_WORDS]
    );
}

fn bytes_as_words(bytes: &[u8; 32]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().unwrap()))
        .collect()
}

const fn raw_column_id(column: usize) -> ArenaSlotId {
    ArenaSlotId(RAW_COLUMN_BASE + column as u32)
}

const fn source_id(column: usize) -> ArenaSlotId {
    ArenaSlotId(SOURCE_BASE + column as u32)
}

const fn output_id(column: usize) -> ArenaSlotId {
    ArenaSlotId(OUTPUT_BASE + column as u32)
}

const fn request(id: ArenaSlotId, words: usize, alignment_words: usize) -> SlotRequest {
    SlotRequest {
        id,
        words,
        alignment_words,
    }
}

fn commit_request(requirement: CommitArenaSlotRequirement) -> SlotRequest {
    request(
        requirement.id,
        requirement.len_words,
        requirement.alignment_words,
    )
}
