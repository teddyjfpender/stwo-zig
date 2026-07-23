//! Native CUDA correctness and capture gate for quotient-to-FRI evaluation.
//!
//! Hardware admission must require exactly one passed test from this target;
//! a CPU/stub build compiles zero tests and is not soundness evidence.

#![cfg(stwo_cuda_link)]

use stwo::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::pcs::quotient_ops::{AccumulatedNumerators, QuotientOps};
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::{TwiddleBuffer, TwiddleTree};
use stwo::prover::secure_column::SecureColumnByCoords;
use stwo_backend_cuda::{
    quotient_workspace_requirements, ArenaLayout, ArenaSlice, ArenaSlotId, ArenaSlotSpec,
    CudaExecContext, DeviceArena, PreparedQuotientGraph, QuotientArenaSlotRequirement,
    QuotientNumeratorSource, QuotientProducerB2nProgram, QuotientSampleConstants,
    QuotientWorkspaceConfig, QuotientWorkspaceSlots,
};

const FORWARD_TWIDDLES: ArenaSlotId = ArenaSlotId(50_000);
const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(50_001);
const PARTIAL_BASE: u32 = 51_000;

fn workspace_slots() -> QuotientWorkspaceSlots {
    let mut next = 1u32;
    let mut id = || {
        let result = ArenaSlotId(next);
        next += 1;
        result
    };
    QuotientWorkspaceSlots {
        sample_points: id(),
        first_linear_terms: id(),
        partial_log_sizes: id(),
        partial_coordinate_ptrs: id(),
        subdomain_coordinate_ptrs: id(),
        output_coordinate_ptrs: id(),
        coefficient_sizes: id(),
        subdomain_values: id(),
        output_values: id(),
    }
}

fn partial_id(source: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(PARTIAL_BASE + (4 * source + coordinate) as u32)
}

fn arena(
    requirements: &stwo_backend_cuda::QuotientWorkspaceRequirements,
    slots: &QuotientWorkspaceSlots,
    logs: &[u32],
) -> DeviceArena {
    let mut requested = requirements.arena_slot_requirements(slots).unwrap();
    requested.extend([
        QuotientArenaSlotRequirement {
            id: FORWARD_TWIDDLES,
            len_words: requirements.forward_twiddle_words,
            alignment_words: 1,
        },
        QuotientArenaSlotRequirement {
            id: INVERSE_TWIDDLES,
            len_words: requirements.inverse_twiddle_words,
            alignment_words: 1,
        },
    ]);
    for (source, &log_size) in logs.iter().enumerate() {
        for coordinate in 0..4 {
            requested.push(QuotientArenaSlotRequirement {
                id: partial_id(source, coordinate),
                len_words: 1usize << log_size,
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

fn compare_outputs(
    left_arena: &DeviceArena,
    left: ArenaSlice,
    right_arena: &DeviceArena,
    right: ArenaSlice,
) -> u64 {
    assert_eq!(left.len_words(), right.len_words());
    const CHUNK_WORDS: usize = 4 * 1024 * 1024;
    let mut digest = 0xcbf2_9ce4_8422_2325u64;
    for first in (0..left.len_words()).step_by(CHUNK_WORDS) {
        let count = CHUNK_WORDS.min(left.len_words() - first);
        let left_words = read(
            left_arena,
            left.checked_subslice(first, count).unwrap(),
            count,
        );
        let right_words = read(
            right_arena,
            right.checked_subslice(first, count).unwrap(),
            count,
        );
        if let Some(index) = left_words
            .iter()
            .zip(&right_words)
            .position(|(left, right)| left != right)
        {
            panic!(
                "quotient output mismatch at word {}: fallback={} candidate={}",
                first + index,
                left_words[index],
                right_words[index]
            );
        }
        for word in right_words {
            digest ^= u64::from(word);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    digest
}

fn secure_words(values: &[SecureField]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn point_words(values: &[CirclePoint<SecureField>]) -> Vec<u32> {
    values
        .iter()
        .flat_map(|point| [point.x, point.y])
        .flat_map(|value| value.to_m31_array().map(|coordinate| coordinate.0))
        .collect()
}

fn partial_values(logs: &[u32], seed: u32) -> Vec<Vec<SecureField>> {
    logs.iter()
        .enumerate()
        .map(|(source, &log_size)| {
            (0..1usize << log_size)
                .map(|row| {
                    let base = seed
                        .wrapping_add(104_729 * (source as u32 + 1))
                        .wrapping_add(7_919 * row as u32);
                    SecureField::from_u32_unchecked(
                        base & 0x3fff_ffff,
                        base.wrapping_mul(3).wrapping_add(5) & 0x3fff_ffff,
                        base.wrapping_mul(5).wrapping_add(7) & 0x3fff_ffff,
                        base.wrapping_mul(7).wrapping_add(11) & 0x3fff_ffff,
                    )
                })
                .collect()
        })
        .collect()
}

fn upload_partials(arena: &DeviceArena, values: &[Vec<SecureField>]) {
    for (source, values) in values.iter().enumerate() {
        for coordinate in 0..4 {
            upload(
                arena,
                partial_id(source, coordinate),
                &values
                    .iter()
                    .map(|value| value.to_m31_array()[coordinate].0)
                    .collect::<Vec<_>>(),
            );
        }
    }
}

fn cpu_output(
    config: QuotientWorkspaceConfig,
    constants: &[QuotientSampleConstants],
    partials: &[Vec<SecureField>],
    twiddles: &TwiddleTree<CpuBackend>,
) -> Vec<u32> {
    let accumulations = constants
        .iter()
        .zip(partials)
        .map(|(constants, partial)| AccumulatedNumerators {
            sample_point: constants.sample_point,
            partial_numerators_acc: partial
                .iter()
                .copied()
                .collect::<SecureColumnByCoords<CpuBackend>>(),
            first_linear_term_acc: constants.first_linear_term_acc,
        })
        .collect();
    let output = CpuBackend::compute_quotients_and_combine(
        accumulations,
        config.lifting_log_size,
        config.log_blowup_factor,
        twiddles,
    );
    output
        .values
        .columns
        .iter()
        .flat_map(|column| column.iter().map(|value| value.0))
        .collect()
}

fn assert_inputs_and_output(
    arena: &DeviceArena,
    prepared: &PreparedQuotientGraph<'_>,
    constants: &[QuotientSampleConstants],
    partials: &[Vec<SecureField>],
    expected_output: &[u32],
) {
    let points = constants
        .iter()
        .map(|constants| constants.sample_point)
        .collect::<Vec<_>>();
    let first_terms = constants
        .iter()
        .map(|constants| constants.first_linear_term_acc)
        .collect::<Vec<_>>();
    assert_eq!(
        read(
            arena,
            prepared.sample_points_destination(),
            8 * constants.len(),
        ),
        point_words(&points)
    );
    assert_eq!(
        read(
            arena,
            prepared.first_linear_terms_destination(),
            4 * constants.len(),
        ),
        secure_words(&first_terms)
    );
    for (source, values) in partials.iter().enumerate() {
        for coordinate in 0..4 {
            assert_eq!(
                read(
                    arena,
                    arena.bind(partial_id(source, coordinate)).unwrap(),
                    values.len(),
                ),
                values
                    .iter()
                    .map(|value| value.to_m31_array()[coordinate].0)
                    .collect::<Vec<_>>()
            );
        }
    }
    assert_eq!(
        read(
            arena,
            prepared.output_evaluation(),
            prepared.requirements().output_value_words,
        ),
        expected_output
    );
}

#[test]
fn quotient_eager_and_capture_match_cpu_constants_partials_and_fri_input() {
    let config = QuotientWorkspaceConfig {
        lifting_log_size: 8,
        log_blowup_factor: 2,
    };
    let logs = [6, 5];
    let requirements = quotient_workspace_requirements(config, &logs).unwrap();
    let slots = workspace_slots();
    let arena = arena(&requirements, &slots, &logs);
    let full_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
    let twiddles = CpuBackend::precompute_twiddles(full_domain.half_coset);
    let inverse_subdomain = twiddles
        .itwiddles
        .extract_subdomain_twiddles(config.lifting_log_size, requirements.subdomain_log_size);
    upload(
        &arena,
        FORWARD_TWIDDLES,
        &twiddles
            .twiddles
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>(),
    );
    upload(
        &arena,
        INVERSE_TWIDDLES,
        &inverse_subdomain
            .iter()
            .map(|value| value.0)
            .collect::<Vec<_>>(),
    );

    let first_constants = [
        QuotientSampleConstants {
            sample_point: SECURE_FIELD_CIRCLE_GEN.mul(3),
            first_linear_term_acc: SecureField::from_u32_unchecked(2, 3, 5, 7),
        },
        QuotientSampleConstants {
            sample_point: SECURE_FIELD_CIRCLE_GEN.mul(7),
            first_linear_term_acc: SecureField::from_u32_unchecked(11, 13, 17, 19),
        },
    ];
    let sources = logs
        .iter()
        .enumerate()
        .map(|(source, &log_size)| QuotientNumeratorSource {
            constants: first_constants[source],
            log_size,
            coordinates: std::array::from_fn(|coordinate| {
                arena.bind(partial_id(source, coordinate)).unwrap()
            }),
        })
        .collect::<Vec<_>>();
    let prepared = PreparedQuotientGraph::prepare(
        &arena,
        config,
        &sources,
        arena.bind(FORWARD_TWIDDLES).unwrap(),
        arena.bind(INVERSE_TWIDDLES).unwrap(),
        &slots,
    )
    .unwrap();

    let first_partials = partial_values(&logs, 23);
    upload_partials(&arena, &first_partials);
    prepared.launch().unwrap();
    assert_inputs_and_output(
        &arena,
        &prepared,
        &first_constants,
        &first_partials,
        &cpu_output(config, &first_constants, &first_partials, &twiddles),
    );

    let capture = arena.context().capture().unwrap();
    prepared.launch().unwrap();
    let graph = capture.finish().unwrap();
    graph.launch(arena.context()).unwrap();
    assert_inputs_and_output(
        &arena,
        &prepared,
        &first_constants,
        &first_partials,
        &cpu_output(config, &first_constants, &first_partials, &twiddles),
    );

    let second_constants = [
        QuotientSampleConstants {
            sample_point: SECURE_FIELD_CIRCLE_GEN.mul(11),
            first_linear_term_acc: SecureField::from_u32_unchecked(23, 29, 31, 37),
        },
        QuotientSampleConstants {
            sample_point: SECURE_FIELD_CIRCLE_GEN.mul(13),
            first_linear_term_acc: SecureField::from_u32_unchecked(41, 43, 47, 53),
        },
    ];
    let second_partials = partial_values(&logs, 0x1234_5678);
    upload_partials(&arena, &second_partials);
    prepared
        .upload_constants_at_transcript_boundary(&second_constants)
        .unwrap();
    graph.launch(arena.context()).unwrap();
    assert_inputs_and_output(
        &arena,
        &prepared,
        &second_constants,
        &second_partials,
        &cpu_output(config, &second_constants, &second_partials, &twiddles),
    );
}

#[test]
#[ignore = "requires exact log23 native CUDA execution"]
fn quotient_producer_b2n_exact_sn2_eager_and_graph_match_fallback() {
    let config = QuotientWorkspaceConfig {
        lifting_log_size: 24,
        log_blowup_factor: 1,
    };
    let logs = (0..19)
        .map(|source| [10, 9, 7][source % 3])
        .collect::<Vec<_>>();
    let requirements = quotient_workspace_requirements(config, &logs).unwrap();
    let slots = workspace_slots();
    let fallback_arena = arena(&requirements, &slots, &logs);
    let candidate_arena = arena(&requirements, &slots, &logs);

    let full_domain = CanonicCoset::new(config.lifting_log_size).circle_domain();
    let twiddles = CpuBackend::precompute_twiddles(full_domain.half_coset);
    let inverse_subdomain = twiddles
        .itwiddles
        .extract_subdomain_twiddles(config.lifting_log_size, requirements.subdomain_log_size);
    let forward_words = twiddles
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let inverse_words = inverse_subdomain
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    for arena in [&fallback_arena, &candidate_arena] {
        upload(arena, FORWARD_TWIDDLES, &forward_words);
        upload(arena, INVERSE_TWIDDLES, &inverse_words);
    }

    let constants = (0..logs.len())
        .map(|source| {
            let value = 101u32.wrapping_mul(source as u32 + 1);
            QuotientSampleConstants {
                sample_point: SECURE_FIELD_CIRCLE_GEN.mul(2 * source as u128 + 3),
                first_linear_term_acc: SecureField::from_u32_unchecked(
                    value,
                    value + 1,
                    value + 3,
                    value + 7,
                ),
            }
        })
        .collect::<Vec<_>>();
    let sources = |arena: &DeviceArena| {
        logs.iter()
            .enumerate()
            .map(|(source, &log_size)| QuotientNumeratorSource {
                constants: constants[source],
                log_size,
                coordinates: std::array::from_fn(|coordinate| {
                    arena.bind(partial_id(source, coordinate)).unwrap()
                }),
            })
            .collect::<Vec<_>>()
    };
    let fallback_sources = sources(&fallback_arena);
    let candidate_sources = sources(&candidate_arena);
    let fallback = PreparedQuotientGraph::prepare(
        &fallback_arena,
        config,
        &fallback_sources,
        fallback_arena.bind(FORWARD_TWIDDLES).unwrap(),
        fallback_arena.bind(INVERSE_TWIDDLES).unwrap(),
        &slots,
    )
    .unwrap();
    let program = QuotientProducerB2nProgram::compile(config, &logs).unwrap();
    let candidate = PreparedQuotientGraph::prepare_with_producer_b2n(
        &candidate_arena,
        config,
        &candidate_sources,
        candidate_arena.bind(FORWARD_TWIDDLES).unwrap(),
        candidate_arena.bind(INVERSE_TWIDDLES).unwrap(),
        &slots,
        program.clone(),
    )
    .unwrap();
    assert_eq!(candidate.producer_b2n_receipt(), Some(program.receipt()));
    let attestation = candidate.producer_b2n_runtime_attestation().unwrap();
    assert_eq!(attestation.sm_arch, 90);
    assert_eq!(attestation.producer.function.binary_version, 90);
    assert_eq!(attestation.producer.launch_threads, 128);
    assert_eq!(attestation.continuations[0].start_stage, 8);
    assert_eq!(attestation.continuations[1].start_stage, 16);
    assert_eq!(attestation.continuations[0].ordinal, 0);
    assert_eq!(attestation.continuations[1].ordinal, 1);
    assert_eq!(
        attestation.continuations[0].function,
        attestation.continuations[1].function
    );

    let eager_partials = partial_values(&logs, 23);
    upload_partials(&fallback_arena, &eager_partials);
    upload_partials(&candidate_arena, &eager_partials);
    fallback.launch().unwrap();
    candidate.launch().unwrap();
    let eager_digest = compare_outputs(
        &fallback_arena,
        fallback.output_evaluation(),
        &candidate_arena,
        candidate.output_evaluation(),
    );

    let fallback_capture = fallback_arena.context().capture().unwrap();
    fallback.launch().unwrap();
    let fallback_graph = fallback_capture.finish().unwrap();
    let candidate_capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = candidate_capture.finish().unwrap();
    assert_eq!(fallback_graph.kernel_nodes(), 28);
    assert_eq!(candidate_graph.kernel_nodes(), 7);

    let replay_partials = partial_values(&logs, 0x1234_5678);
    upload_partials(&fallback_arena, &replay_partials);
    upload_partials(&candidate_arena, &replay_partials);
    let replay_constants = constants
        .iter()
        .enumerate()
        .map(|(source, constants)| QuotientSampleConstants {
            sample_point: SECURE_FIELD_CIRCLE_GEN.mul(2 * source as u128 + 43),
            first_linear_term_acc: constants.first_linear_term_acc
                + SecureField::from_u32_unchecked(109, 113, 127, 131),
        })
        .collect::<Vec<_>>();
    fallback
        .upload_constants_at_transcript_boundary(&replay_constants)
        .unwrap();
    candidate
        .upload_constants_at_transcript_boundary(&replay_constants)
        .unwrap();
    fallback_graph.launch(fallback_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    let replay_digest = compare_outputs(
        &fallback_arena,
        fallback.output_evaluation(),
        &candidate_arena,
        candidate.output_evaluation(),
    );
    assert_ne!(eager_digest, replay_digest);
}
