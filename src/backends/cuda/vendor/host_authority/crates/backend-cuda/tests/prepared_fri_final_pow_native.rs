//! Native CUDA correctness and capture gate for final FRI and proof-of-work.
//!
//! Hardware admission must require exactly three passed tests from this target;
//! a CPU/stub build compiles zero tests and is not soundness evidence.

#![cfg(stwo_cuda_link)]

use stwo::core::channel::{Blake2sChannelGeneric, Channel};
use stwo::core::circle::Coset;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::poly::line::{LineDomain, LinePoly};
use stwo::core::proof_of_work::GrindOps;
use stwo::core::utils::bit_reverse_index;
use stwo::prover::backend::cpu::circle::slow_precompute_twiddles;
use stwo::prover::backend::simd::SimdBackend;
use stwo_backend_cuda::{
    blake2s_pow_workspace_requirements, fri_final_workspace_requirements, pow_index_to_nonce,
    ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec, Blake2sPowArenaSlotRequirement,
    Blake2sPowFleetAttempt, Blake2sPowWorkspaceSlots, CudaExecContext, DeviceArena,
    FriFinalArenaSlotRequirement, FriFinalWorkspaceSlots, FriWorkspaceConfig,
    PreparedBlake2sPowGraph, PreparedFriEvaluation, PreparedFriFinalGraph,
};

const FRI_EVALUATION: ArenaSlotId = ArenaSlotId(50_000);
const FRI_POINTERS: ArenaSlotId = ArenaSlotId(50_001);
const FRI_TWIDDLES: ArenaSlotId = ArenaSlotId(50_002);
const FRI_TRANSCRIPT: ArenaSlotId = ArenaSlotId(50_003);
const FRI_COEFFICIENTS: ArenaSlotId = ArenaSlotId(50_004);
const FRI_DEGREE_ERROR: ArenaSlotId = ArenaSlotId(50_005);

const POW_STATE: ArenaSlotId = ArenaSlotId(60_000);
const POW_NONCE: ArenaSlotId = ArenaSlotId(60_001);
const POW_BEST: ArenaSlotId = ArenaSlotId(60_002);
const POW_COMPLETED: ArenaSlotId = ArenaSlotId(60_003);
const POW_PREFIX: ArenaSlotId = ArenaSlotId(60_004);

fn arena_from_requirements(
    requirements: impl IntoIterator<Item = (ArenaSlotId, usize, usize)>,
) -> DeviceArena {
    let mut offset = 0usize;
    let specs = requirements
        .into_iter()
        .map(|(id, len_words, alignment_words)| {
            offset = offset.next_multiple_of(alignment_words);
            let spec = ArenaSlotSpec {
                id,
                offset_words: offset,
                len_words,
                alignment_words,
            };
            offset += len_words;
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

fn read(arena: &DeviceArena, source: ArenaSlice, words: usize) -> Vec<u32> {
    let mut host = vec![0u32; words];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                host.as_mut_ptr().cast(),
                source.as_void_ptr(),
                words * core::mem::size_of::<u32>(),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    host
}

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn bit_reversed_line_evaluations(
    domain: LineDomain,
    ordered_coefficients: Vec<SecureField>,
) -> Vec<u32> {
    let log_size = domain.log_size();
    let polynomial = LinePoly::from_ordered_coefficients(ordered_coefficients);
    let evaluations = (0..domain.size())
        .map(|index| polynomial.eval_at_point(domain.at(bit_reverse_index(index, log_size)).into()))
        .collect::<Vec<_>>();
    (0..4)
        .flat_map(|coordinate| {
            evaluations
                .iter()
                .map(move |value| value.to_m31_array()[coordinate].0)
        })
        .collect()
}

fn expected_last_poly_words(ordered_coefficients: &[SecureField], degree: usize) -> Vec<u32> {
    let retained = LinePoly::from_ordered_coefficients(ordered_coefficients[..degree].to_vec());
    secure_words(&retained)
}

#[test]
fn final_fri_eager_and_capture_match_reference_bytes_and_reject_high_coefficients() {
    let config = FriWorkspaceConfig {
        fri: FriConfig::new(2, 1, 16, 2),
        circle_log_size: 6,
        twiddle_log_size: 5,
    };
    let requirements = fri_final_workspace_requirements(config).unwrap();
    assert_eq!(requirements.evaluation_log_size, 3);
    let workspace_slots = FriFinalWorkspaceSlots {
        coefficients: FRI_COEFFICIENTS,
        degree_error: FRI_DEGREE_ERROR,
    };
    let mut requested = requirements
        .arena_slot_requirements(workspace_slots)
        .unwrap()
        .into_iter()
        .map(|requirement: FriFinalArenaSlotRequirement| {
            (
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            )
        })
        .collect::<Vec<_>>();
    requested.extend([
        (FRI_EVALUATION, requirements.evaluation_words, 1),
        (FRI_POINTERS, 8, 2),
        (FRI_TWIDDLES, requirements.inverse_twiddle_words, 1),
        (FRI_TRANSCRIPT, requirements.transcript_words, 1),
    ]);
    let arena = arena_from_requirements(requested);

    let root = Coset::half_odds(config.circle_log_size - 1);
    let domain = LineDomain::new(
        root.repeated_double(config.circle_log_size - 1 - requirements.evaluation_log_size),
    );
    let inverse_twiddles = slow_precompute_twiddles(root)
        .into_iter()
        .map(|value| value.inverse().0)
        .collect::<Vec<_>>();
    upload(&arena, FRI_TWIDDLES, &inverse_twiddles);

    let evaluation = PreparedFriEvaluation {
        values: arena.bind(FRI_EVALUATION).unwrap(),
        coordinate_ptrs: arena.bind(FRI_POINTERS).unwrap(),
        coordinate_stride: domain.size(),
        log_size: domain.log_size(),
    };
    let prepared = PreparedFriFinalGraph::prepare(
        &arena,
        config,
        evaluation,
        arena.bind(FRI_TWIDDLES).unwrap(),
        arena.bind(FRI_TRANSCRIPT).unwrap(),
        workspace_slots,
    )
    .unwrap();

    let first = vec![
        SecureField::from_u32_unchecked(3, 5, 7, 11),
        SecureField::from_u32_unchecked(13, 17, 19, 23),
        SecureField::from_u32_unchecked(29, 31, 37, 41),
        SecureField::from_u32_unchecked(43, 47, 53, 59),
        SecureField::from(0u32),
        SecureField::from(0u32),
        SecureField::from(0u32),
        SecureField::from(0u32),
    ];
    upload(
        &arena,
        FRI_EVALUATION,
        &bit_reversed_line_evaluations(domain, first.clone()),
    );
    prepared.launch().unwrap();
    assert_eq!(
        read(
            &arena,
            prepared.transcript_destination(),
            requirements.transcript_words,
        ),
        expected_last_poly_words(&first, 1 << config.fri.log_last_layer_degree_bound)
    );
    assert_eq!(read(&arena, prepared.degree_error(), 1), [0]);

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    let second = vec![
        SecureField::from_u32_unchecked(61, 67, 71, 73),
        SecureField::from_u32_unchecked(79, 83, 89, 97),
        SecureField::from_u32_unchecked(101, 103, 107, 109),
        SecureField::from_u32_unchecked(113, 127, 131, 137),
        SecureField::from(0u32),
        SecureField::from(0u32),
        SecureField::from(0u32),
        SecureField::from(0u32),
    ];
    upload(
        &arena,
        FRI_EVALUATION,
        &bit_reversed_line_evaluations(domain, second.clone()),
    );
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        read(
            &arena,
            prepared.transcript_destination(),
            requirements.transcript_words,
        ),
        expected_last_poly_words(&second, 1 << config.fri.log_last_layer_degree_bound)
    );
    assert_eq!(read(&arena, prepared.degree_error(), 1), [0]);

    let mut invalid = second;
    invalid[7] = SecureField::from_u32_unchecked(139, 149, 151, 157);
    upload(
        &arena,
        FRI_EVALUATION,
        &bit_reversed_line_evaluations(domain, invalid),
    );
    graph.launch(arena.context()).unwrap();
    assert_eq!(read(&arena, prepared.degree_error(), 1), [1]);
    assert_eq!(
        read(&arena, prepared.transcript_destination(), 1),
        [0x7fff_ffff]
    );
}

fn transcript_state(channel: &Blake2sChannelGeneric<false>) -> [u32; 16] {
    let mut state = [0u32; 16];
    for (destination, bytes) in state[..8]
        .iter_mut()
        .zip(channel.digest().0.chunks_exact(4))
    {
        *destination = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    state
}

fn read_nonce(arena: &DeviceArena, nonce: ArenaSlice) -> u64 {
    let words = read(arena, nonce, 2);
    u64::from(words[0]) | (u64::from(words[1]) << 32)
}

// The byte-identity contract is the SIMD grind: the smallest qualifying nonce
// on the lattice {(hi << 32) | low : 0 <= low < 2^20}, whose (hi asc, low asc)
// scan order equals numeric order on the lattice. At pow_bits = 10 the answer
// lands in the first low block with overwhelming probability, but the pinned
// reference must be SimdBackend::grind — a dense-scan (CpuBackend) reference
// would diverge whenever the dense minimum has low-32 bits >= 2^20.
#[test]
fn persistent_pow_eager_and_capture_return_simd_lattice_minimum() {
    let requirements = blake2s_pow_workspace_requirements();
    let workspace_slots = Blake2sPowWorkspaceSlots {
        best_nonce: POW_BEST,
        completed_blocks: POW_COMPLETED,
        prefix_digest: POW_PREFIX,
    };
    let mut requested = requirements
        .arena_slot_requirements(workspace_slots)
        .unwrap()
        .into_iter()
        .map(|requirement: Blake2sPowArenaSlotRequirement| {
            (
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            )
        })
        .collect::<Vec<_>>();
    requested.extend([
        (POW_STATE, requirements.state_words, 8),
        (POW_NONCE, requirements.nonce_words, 2),
    ]);
    let arena = arena_from_requirements(requested);
    let pow_bits = 10;
    let prepared = PreparedBlake2sPowGraph::prepare(
        &arena,
        arena.bind(POW_STATE).unwrap(),
        pow_bits,
        arena.bind(POW_NONCE).unwrap(),
        workspace_slots,
    )
    .unwrap();

    let mut first_channel = Blake2sChannelGeneric::<false>::default();
    first_channel.mix_u32s(&[1, 0x1122_3344, 0xaabb_ccdd]);
    upload(&arena, POW_STATE, &transcript_state(&first_channel));
    prepared.launch().unwrap();
    assert_eq!(
        read_nonce(&arena, prepared.nonce_destination()),
        SimdBackend::grind(&first_channel, pow_bits)
    );

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    let mut second_channel = Blake2sChannelGeneric::<false>::default();
    second_channel.mix_u32s(&[42, 77, 99, 0xdead_beef]);
    upload(&arena, POW_STATE, &transcript_state(&second_channel));
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        read_nonce(&arena, prepared.nonce_destination()),
        SimdBackend::grind(&second_channel, pow_bits)
    );
}

fn host_rank_minimum(
    channel: &Blake2sChannelGeneric<false>,
    pow_bits: u32,
    attempt: Blake2sPowFleetAttempt,
    rank: u32,
) -> u64 {
    let workers_per_rank =
        u64::from(attempt.grid_blocks()) * u64::from(stwo_backend_cuda::POW_THREADS_PER_BLOCK);
    let stride = workers_per_rank * u64::from(attempt.rank_count());
    (attempt.start_index()..attempt.end_index())
        .filter(|index| (index % stride) / workers_per_rank == u64::from(rank))
        .map(pow_index_to_nonce)
        .find(|&nonce| channel.verify_pow_nonce(pow_bits, nonce))
        .unwrap_or(u64::MAX)
}

#[test]
fn fleet_pow_rank_tiles_match_independent_host_minima_and_capture_replay() {
    let requirements = blake2s_pow_workspace_requirements();
    let workspace_slots = Blake2sPowWorkspaceSlots {
        best_nonce: POW_BEST,
        completed_blocks: POW_COMPLETED,
        prefix_digest: POW_PREFIX,
    };
    let mut requested = requirements
        .arena_slot_requirements(workspace_slots)
        .unwrap()
        .into_iter()
        .map(|requirement: Blake2sPowArenaSlotRequirement| {
            (
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            )
        })
        .collect::<Vec<_>>();
    requested.extend([
        (POW_STATE, requirements.state_words, 8),
        (POW_NONCE, requirements.nonce_words, 2),
    ]);
    let arena = arena_from_requirements(requested);
    let pow_bits = 10;
    let prepared = PreparedBlake2sPowGraph::prepare(
        &arena,
        arena.bind(POW_STATE).unwrap(),
        pow_bits,
        arena.bind(POW_NONCE).unwrap(),
        workspace_slots,
    )
    .unwrap();

    let mut channel = Blake2sChannelGeneric::<false>::default();
    channel.mix_u32s(&[7, 0x1234_5678, 0x90ab_cdef]);
    prepared.upload_state(&transcript_state(&channel)).unwrap();
    let attempt = Blake2sPowFleetAttempt::new(4, 17, 65_554, 2).unwrap();
    let mut rank_minima = Vec::new();
    for rank in 0..attempt.rank_count() {
        prepared
            .launch_rank_tile(attempt.rank_tile(rank).unwrap())
            .unwrap();
        let actual = prepared.read_rank_result().unwrap();
        assert_eq!(
            actual,
            host_rank_minimum(&channel, pow_bits, attempt, rank),
            "rank {rank}"
        );
        rank_minima.push(actual);
    }
    let actual_global = rank_minima.into_iter().min().unwrap();
    let expected_global = (attempt.start_index()..attempt.end_index())
        .map(pow_index_to_nonce)
        .find(|&nonce| channel.verify_pow_nonce(pow_bits, nonce))
        .unwrap_or(u64::MAX);
    assert_eq!(actual_global, expected_global);

    let no_hit_start = (0..10_000)
        .find(|&start| {
            (start..start + 17)
                .map(pow_index_to_nonce)
                .all(|nonce| !channel.verify_pow_nonce(pow_bits, nonce))
        })
        .unwrap();
    let no_hit = Blake2sPowFleetAttempt::new(2, no_hit_start, no_hit_start + 17, 1).unwrap();
    for rank in 0..no_hit.rank_count() {
        prepared
            .launch_rank_tile(no_hit.rank_tile(rank).unwrap())
            .unwrap();
        assert_eq!(prepared.read_rank_result().unwrap(), u64::MAX);
    }

    let captured_rank = attempt.rank_tile(0).unwrap();
    let capture = arena.context().capture().unwrap();
    prepared.launch_rank_tile(captured_rank).unwrap();
    let graph = capture.finish().unwrap();
    let mut replay_channel = Blake2sChannelGeneric::<false>::default();
    replay_channel.mix_u32s(&[11, 22, 33, 44, 55]);
    prepared
        .upload_state(&transcript_state(&replay_channel))
        .unwrap();
    graph.launch(arena.context()).unwrap();
    assert_eq!(
        prepared.read_rank_result().unwrap(),
        host_rank_minimum(&replay_channel, pow_bits, attempt, 0)
    );
}
