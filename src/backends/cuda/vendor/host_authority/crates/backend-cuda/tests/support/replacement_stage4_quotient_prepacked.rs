use std::collections::BTreeMap;

use stwo::core::circle::{CirclePoint, SECURE_FIELD_CIRCLE_GEN};
use stwo::core::constraints::complex_conjugate_line_coeffs;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fields::FieldExpOps;
use stwo::core::pcs::quotients::PointSample;
use stwo_backend_cuda::{
    quotient_numerator_prepacked_plan_identity, quotient_numerator_prepacked_row_oracle,
    quotient_numerator_prepacked_term_layout, quotient_numerator_prepacked_term_oracle,
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    quotient_numerator_workspace_requirements, DeviceArena, PreparedNumeratorSchedule,
    PreparedQuotientNumeratorError, PreparedQuotientNumeratorGraph, QuotientNumeratorColumn,
    QuotientNumeratorColumnTopology, QuotientNumeratorDestination,
    QuotientNumeratorLineCoefficientsWords, QuotientNumeratorPrepackedStatusCode,
    QuotientNumeratorWorkspaceConfig, QuotientNumeratorWorkspaceRequirements,
    QuotientNumeratorWorkspaceSlots, QuotientOodsSample,
};

use super::quotient_numerator_oracle::{expected_group, OracleTerm};
#[cfg(stwo_cuda_link)]
use super::replacement_stage4_common::{
    cuda_event_abba_timings, LoadedFunctionReceipt, PerformanceReceipt,
};
use super::replacement_stage4_common::{
    fill, hash_words, read_words, upload_words, FixtureReceipt,
};
use super::replacement_stage4_quotient as quotient;
#[cfg(stwo_cuda_link)]
use super::replacement_stage4_quotient_resources::loaded_function_receipts;

const OVERFLOW_WORDS: usize = 128;
const STALE_OUTPUT_BYTE: u8 = 0x5a;

pub fn run() -> FixtureReceipt {
    let config = config(10);
    let points = points();
    let topology = dense_topology(quotient::topology(points), points);
    let requirements = quotient_numerator_workspace_requirements(config, &topology).unwrap();
    let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &topology,
        &[OVERFLOW_WORDS],
    )
    .unwrap();
    let layout = quotient_numerator_prepacked_term_layout(&plan).unwrap();
    let slots = quotient::workspace_slots(&requirements);
    let source_words = [1 << 3, 1 << 5, 1 << 5, 1 << 3];
    let (baseline_arena, baseline_bytes) =
        quotient::make_arena(&requirements, &slots, source_words, OVERFLOW_WORDS);
    let (candidate_arena, candidate_bytes) =
        quotient::make_arena(&requirements, &slots, source_words, OVERFLOW_WORDS);
    let values = values();
    let eager_sources = quotient::source_set(0x1234_5678);
    let replay_sources = quotient::source_set(0x6a09_e667);
    let twiddles = quotient::required_forward_twiddle_words(config, &requirements);
    initialize(
        [&baseline_arena, &candidate_arena],
        points,
        &values,
        &twiddles,
        &eager_sources,
    );

    let baseline_destinations = quotient::destinations(&baseline_arena, &requirements);
    let candidate_destinations = quotient::destinations(&candidate_arena, &requirements);
    let baseline_columns = quotient::columns(&baseline_arena, &topology);
    let candidate_columns = quotient::columns(&candidate_arena, &topology);
    let baseline = prepare_staged(
        &baseline_arena,
        config,
        &slots,
        &baseline_columns,
        &baseline_destinations,
    );
    let candidate = prepare_prepacked(
        &candidate_arena,
        config,
        &slots,
        &candidate_columns,
        &candidate_destinations,
    );
    assert_eq!(
        candidate.schedule(),
        PreparedNumeratorSchedule::StagedPrepackedSingleWrite {
            packed_output_rows: plan.packed_output_rows(),
        }
    );
    let receipt = candidate.prepacked_receipt().unwrap();
    assert_eq!(
        receipt.plan_identity,
        quotient_numerator_prepacked_plan_identity(&plan).unwrap()
    );
    assert_eq!(receipt.source_count as usize, plan.sources().len());
    assert_eq!(receipt.used_words as usize, layout.used_words);
    assert_eq!(receipt.status_offset_words, layout.status_offset_words);
    assert!(layout.term_count >= 4 * layout.group_count + 1);
    assert!(layout.used_words <= requirements.term_point_words);

    let eager_alpha = SecureField::from_u32_unchecked(73, 79, 83, 89);
    upload_alpha([&baseline_arena, &candidate_arena], eager_alpha);
    baseline.launch().unwrap();
    candidate.launch().unwrap();
    let d2h_before = candidate_arena.context().telemetry().d2h_bytes;
    candidate.observe_prepacked_status().unwrap();
    assert_eq!(
        candidate_arena.context().telemetry().d2h_bytes - d2h_before,
        core::mem::size_of::<u32>() as u64
    );
    let eager_evaluations = quotient::evaluations(config, &eager_sources);
    let eager_baseline = dense_snapshot(
        &baseline_arena,
        &requirements,
        &baseline_destinations,
        &topology,
        &values,
        eager_alpha,
        &eager_evaluations,
    );
    let eager_candidate = dense_snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &topology,
        &values,
        eager_alpha,
        &eager_evaluations,
    );
    assert_eq!(eager_candidate, eager_baseline);

    let capture = baseline_arena.context().capture().unwrap();
    baseline.launch().unwrap();
    let baseline_graph = capture.finish().unwrap();
    let capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();

    let replay_alpha = SecureField::from_u32_unchecked(97, 101, 103, 107);
    for arena in [&baseline_arena, &candidate_arena] {
        quotient::upload_sources(arena, &replay_sources);
    }
    upload_alpha([&baseline_arena, &candidate_arena], replay_alpha);
    baseline_graph.launch(baseline_arena.context()).unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    candidate.observe_prepacked_status().unwrap();
    let replay_evaluations = quotient::evaluations(config, &replay_sources);
    let replay_baseline = dense_snapshot(
        &baseline_arena,
        &requirements,
        &baseline_destinations,
        &topology,
        &values,
        replay_alpha,
        &replay_evaluations,
    );
    let replay_candidate = dense_snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &topology,
        &values,
        replay_alpha,
        &replay_evaluations,
    );
    assert_eq!(replay_candidate, replay_baseline);
    assert_ne!(eager_candidate, replay_candidate);

    fill_outputs(&candidate_arena, &candidate_destinations, STALE_OUTPUT_BYTE);
    let mut invalid_descriptors = plan.term_descriptors().to_vec();
    invalid_descriptors[0] = u32::MAX;
    upload_words(
        &candidate_arena,
        candidate_arena.bind(slots.batch_terms).unwrap(),
        &invalid_descriptors,
    );
    candidate_arena.context().sync().unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    assert!(matches!(
        candidate.observe_prepacked_status(),
        Err(PreparedQuotientNumeratorError::PrepackedDeviceStatus(status))
            if status
                == QuotientNumeratorPrepackedStatusCode::PrepareSourceOutOfBounds.as_u32()
    ));
    assert_outputs_still_filled(&candidate_arena, &candidate_destinations, STALE_OUTPUT_BYTE);

    upload_words(
        &candidate_arena,
        candidate_arena.bind(slots.batch_terms).unwrap(),
        plan.term_descriptors(),
    );
    fill_outputs(&candidate_arena, &candidate_destinations, 0xa6);
    candidate_arena.context().sync().unwrap();
    candidate_graph.launch(candidate_arena.context()).unwrap();
    candidate.observe_prepacked_status().unwrap();
    let recovered = dense_snapshot(
        &candidate_arena,
        &requirements,
        &candidate_destinations,
        &topology,
        &values,
        replay_alpha,
        &replay_evaluations,
    );
    assert_eq!(recovered, replay_baseline);
    quotient::assert_preserved(&baseline_arena, &replay_sources);
    quotient::assert_preserved(&candidate_arena, &replay_sources);

    let hashes = [
        ("eager_outputs".to_owned(), hash_words(&eager_candidate)),
        ("replay_outputs".to_owned(), hash_words(&replay_candidate)),
        ("reset_recovery_outputs".to_owned(), hash_words(&recovered)),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let checks = [
        ("exact_plan_receipt", true),
        ("dense_native_independent_cpu_oracle", true),
        ("eager_staged_prepacked_identity", true),
        ("captured_replay_status_reset", true),
        ("invalid_descriptor_rejects_stale_output", true),
        ("replay_recovers_after_status_error", true),
        ("source_and_guard_preservation", true),
    ]
    .into_iter()
    .map(|(name, passed)| (name.to_owned(), passed))
    .collect();
    FixtureReceipt {
        name: "staged-prepacked-quotient-boundary",
        production_apis: vec![
            "PreparedQuotientNumeratorGraph::prepare_staged_prepacked_single_write_candidate",
            "PreparedQuotientNumeratorGraph::observe_prepacked_status",
        ],
        cases: 4,
        arena_bytes: baseline_bytes + candidate_bytes,
        checks,
        hashes,
    }
}

#[cfg(stwo_cuda_link)]
pub fn benchmark(
    lifting_log_size: u32,
    warmups: usize,
    iterations: usize,
) -> Vec<PerformanceReceipt> {
    let config = config(lifting_log_size);
    let points = points();
    let topology = dense_topology(quotient::scaled_topology(points, lifting_log_size), points);
    let source_words = [
        1usize << (lifting_log_size - 3),
        1usize << (lifting_log_size - 1),
        1usize << (lifting_log_size - 2),
        1usize << (lifting_log_size - 3),
    ];
    let overflow_words = 1usize << lifting_log_size;
    let requirements = quotient_numerator_workspace_requirements(config, &topology).unwrap();
    let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &topology,
        &[overflow_words],
    )
    .unwrap();
    let layout = quotient_numerator_prepacked_term_layout(&plan).unwrap();
    assert!(layout.term_count >= 4 * layout.group_count + 1);
    let slots = quotient::workspace_slots(&requirements);
    let (arena, arena_bytes) =
        quotient::make_arena(&requirements, &slots, source_words, overflow_words);
    let values = values();
    let sources = quotient::source_set_for_words(0x1319_8a2e, source_words);
    let twiddles = quotient::required_forward_twiddle_words(config, &requirements);
    initialize([&arena], points, &values, &twiddles, &sources);
    upload_alpha([&arena], SecureField::from_u32_unchecked(73, 79, 83, 89));

    let destinations = quotient::destinations(&arena, &requirements);
    let columns = quotient::columns(&arena, &topology);
    let baseline = prepare_staged(&arena, config, &slots, &columns, &destinations);
    let candidate = prepare_prepacked(&arena, config, &slots, &columns, &destinations);
    let loaded_functions = loaded_function_receipts();
    let status_observations = warmups.checked_add(iterations).unwrap();
    let expected_fence_bytes = (status_observations * core::mem::size_of::<u32>()) as u64;

    let eager_d2h_before = arena.context().telemetry().d2h_bytes;
    let eager = cuda_event_abba_timings(
        arena.context(),
        warmups,
        iterations,
        || baseline.launch(),
        || candidate.launch(),
        || arena.context().sync().unwrap(),
        || candidate.observe_prepacked_status().unwrap(),
    );
    assert_eq!(
        arena.context().telemetry().d2h_bytes - eager_d2h_before,
        expected_fence_bytes
    );

    let capture = arena.context().capture().unwrap();
    baseline.launch().unwrap();
    let baseline_graph = capture.finish().unwrap();
    let capture = arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    let captured_d2h_before = arena.context().telemetry().d2h_bytes;
    let captured = cuda_event_abba_timings(
        arena.context(),
        warmups,
        iterations,
        || baseline_graph.launch(arena.context()),
        || candidate_graph.launch(arena.context()),
        || arena.context().sync().unwrap(),
        || candidate.observe_prepacked_status().unwrap(),
    );
    assert_eq!(
        arena.context().telemetry().d2h_bytes - captured_d2h_before,
        expected_fence_bytes
    );

    baseline.launch().unwrap();
    arena.context().sync().unwrap();
    let baseline_output = quotient::raw_snapshot(&arena, &requirements, &destinations);
    candidate.launch().unwrap();
    candidate.observe_prepacked_status().unwrap();
    let candidate_output = quotient::raw_snapshot(&arena, &requirements, &destinations);
    assert_eq!(baseline_output, candidate_output);
    quotient::assert_preserved(&arena, &sources);

    let receipt = |mode: &str,
                   (baseline_timing, candidate_timing),
                   loaded_functions: Vec<LoadedFunctionReceipt>| {
        PerformanceReceipt {
            name: format!("staged-prepacked-quotient-{mode}-log{lifting_log_size}"),
            parameters: [
                ("lifting_log_size".to_owned(), u64::from(lifting_log_size)),
                ("groups".to_owned(), requirements.groups.len() as u64),
                ("terms".to_owned(), requirements.term_count as u64),
                ("packed_output_rows".to_owned(), plan.packed_output_rows()),
                ("prepacked_used_words".to_owned(), layout.used_words as u64),
                (
                    "candidate_status_observations".to_owned(),
                    status_observations as u64,
                ),
                ("stream_count".to_owned(), 1),
                ("source_buffer_sets".to_owned(), 1),
            ]
            .into_iter()
            .collect(),
            arena_bytes: [("shared_single_stream".to_owned(), arena_bytes)]
                .into_iter()
                .collect(),
            traffic_bytes: [
                (
                    "prepacked_record_bytes".to_owned(),
                    (layout.used_words * core::mem::size_of::<u32>()) as u64,
                ),
                (
                    "candidate_status_fence_d2h_bytes_per_replay_outside_kernel_time".to_owned(),
                    core::mem::size_of::<u32>() as u64,
                ),
                (
                    "candidate_status_fence_d2h_bytes_total_outside_kernel_time".to_owned(),
                    expected_fence_bytes,
                ),
            ]
            .into_iter()
            .collect(),
            loaded_functions,
            baseline_label: format!("staged-packed-single-write-{mode}-checked-abba"),
            candidate_label: format!("staged-prepacked-single-write-{mode}-checked-abba"),
            baseline: baseline_timing,
            candidate: candidate_timing,
            speedup: baseline_timing.median_ms / candidate_timing.median_ms,
        }
    };
    vec![
        receipt("eager", eager, loaded_functions.clone()),
        receipt("captured", captured, loaded_functions),
    ]
}

fn config(lifting_log_size: u32) -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1usize << lifting_log_size),
    }
}

fn points() -> [CirclePoint<SecureField>; 4] {
    [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ]
}

fn values() -> [SecureField; 5] {
    [
        SecureField::from_u32_unchecked(2, 3, 5, 7),
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
        SecureField::from_u32_unchecked(41, 43, 47, 53),
        SecureField::from_u32_unchecked(59, 61, 67, 71),
    ]
}

fn dense_topology(
    mut topology: Vec<QuotientNumeratorColumnTopology>,
    points: [CirclePoint<SecureField>; 4],
) -> Vec<QuotientNumeratorColumnTopology> {
    assert_eq!(topology.len(), 4);
    let sample = |input_index, shape_point| QuotientOodsSample {
        input_index,
        shape_point,
    };
    topology[0].samples = vec![
        sample(0, points[0]),
        sample(1, points[1]),
        sample(0, points[0]),
        sample(1, points[1]),
        sample(0, points[0]),
    ];
    topology[1].samples = vec![sample(2, points[0]); 5];
    topology[2].samples = vec![sample(3, points[2]); 5];
    topology[3].samples = vec![sample(4, points[3]); 5];
    assert!(topology.iter().all(|column| column.samples.len() != 2));
    topology
}

fn dense_snapshot(
    arena: &DeviceArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    destinations: &[QuotientNumeratorDestination],
    topology: &[QuotientNumeratorColumnTopology],
    values: &[SecureField; 5],
    alpha: SecureField,
    sources: &[Vec<u32>; 4],
) -> Vec<u32> {
    let terms = dense_oracle_terms(topology, values, sources);
    assert_eq!(terms.len(), requirements.term_count);
    quotient::snapshot_from_terms(arena, requirements, destinations, alpha, &terms)
}

fn dense_oracle_terms<'a>(
    topology: &[QuotientNumeratorColumnTopology],
    values: &[SecureField; 5],
    sources: &'a [Vec<u32>; 4],
) -> Vec<OracleTerm<'a>> {
    let mut exponent = 0;
    let mut terms = Vec::with_capacity(topology.iter().map(|column| column.samples.len()).sum());
    for (column, shape) in topology.iter().enumerate() {
        for sample in &shape.samples {
            terms.push(OracleTerm {
                exponent,
                source_log: shape.coefficient_log_size,
                value: values[sample.input_index as usize],
                point: sample.shape_point,
                source: &sources[column],
            });
            exponent += 1;
        }
    }
    terms
}

#[test]
fn dense_fixture_matches_staged_term_manifest_and_fits_dead_extent() {
    let config = config(10);
    let points = points();
    let topology = dense_topology(quotient::topology(points), points);
    let plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &topology,
        &[OVERFLOW_WORDS],
    )
    .unwrap();
    let layout = quotient_numerator_prepacked_term_layout(&plan).unwrap();
    let sources = quotient::evaluations(config, &quotient::source_set(0x1234_5678));
    let values = values();
    let terms = dense_oracle_terms(&topology, &values, &sources);
    let mut descriptor_terms = plan
        .term_descriptors()
        .chunks_exact(3)
        .map(|descriptor| descriptor[1] as usize)
        .collect::<Vec<_>>();
    descriptor_terms.sort_unstable();

    assert_eq!(
        topology
            .iter()
            .map(|column| column.samples.len())
            .sum::<usize>(),
        20
    );
    assert_eq!(plan.requirements().term_count, 20);
    assert_eq!(plan.requirements().groups.len(), 4);
    assert_eq!(
        terms.iter().map(|term| term.exponent).collect::<Vec<_>>(),
        (0..20).collect::<Vec<_>>()
    );
    assert_eq!(descriptor_terms, (0..20).collect::<Vec<_>>());
    assert_eq!(layout.used_words, 157);
    assert_eq!(layout.term_point_capacity_words, 160);
    assert_eq!(layout.spare_words(), 3);

    let alpha = SecureField::from_u32_unchecked(73, 79, 83, 89);
    let coefficients = terms
        .iter()
        .map(|term| {
            let (_, b, c) = complex_conjugate_line_coeffs(
                &PointSample {
                    point: term.point,
                    value: term.value,
                },
                alpha.pow(term.exponent as u128),
            );
            QuotientNumeratorLineCoefficientsWords {
                b: b.to_m31_array().map(|word| word.0),
                c: c.to_m31_array().map(|word| word.0),
            }
        })
        .collect::<Vec<_>>();
    let packed = quotient_numerator_prepacked_term_oracle(&plan, &coefficients).unwrap();
    let staged_sources = plan
        .sources()
        .iter()
        .map(|source| sources[source.column()].clone())
        .collect::<Vec<_>>();
    for (group, requirements) in plan.requirements().groups.iter().enumerate() {
        let (_, expected) = expected_group(
            requirements.shape_point,
            requirements.log_size,
            alpha,
            &terms,
        );
        for row in 0..requirements.value_words {
            assert_eq!(
                quotient_numerator_prepacked_row_oracle(
                    &plan,
                    &packed,
                    &staged_sources,
                    group,
                    row,
                )
                .unwrap(),
                std::array::from_fn(|coordinate| expected[coordinate][row])
            );
        }
    }
}

fn initialize<const N: usize>(
    arenas: [&DeviceArena; N],
    points: [CirclePoint<SecureField>; 4],
    values: &[SecureField; 5],
    twiddles: &[u32],
    sources: &[Vec<u32>; 4],
) {
    for arena in arenas {
        upload_words(
            arena,
            arena.bind(quotient::OODS_POINTS).unwrap(),
            &quotient::point_words(&[points[0], points[1], points[0], points[2], points[3]]),
        );
        upload_words(
            arena,
            arena.bind(quotient::OODS_VALUES).unwrap(),
            &quotient::secure_words(values),
        );
        upload_words(arena, arena.bind(quotient::TWIDDLES).unwrap(), twiddles);
        quotient::upload_sources(arena, sources);
        fill(arena, arena.bind(quotient::GUARD).unwrap(), 0xa5);
        arena.context().sync().unwrap();
    }
}

fn upload_alpha<const N: usize>(arenas: [&DeviceArena; N], alpha: SecureField) {
    for arena in arenas {
        upload_words(
            arena,
            arena.bind(quotient::ALPHA).unwrap(),
            &quotient::secure_words(&[alpha]),
        );
    }
}

fn prepare_staged<'a>(
    arena: &'a DeviceArena,
    config: QuotientNumeratorWorkspaceConfig,
    slots: &QuotientNumeratorWorkspaceSlots,
    columns: &[QuotientNumeratorColumn],
    destinations: &[QuotientNumeratorDestination],
) -> PreparedQuotientNumeratorGraph<'a> {
    PreparedQuotientNumeratorGraph::prepare_staged_packed_single_write(
        arena,
        config,
        columns,
        arena.bind(quotient::OODS_POINTS).unwrap(),
        arena.bind(quotient::OODS_VALUES).unwrap(),
        arena.bind(quotient::ALPHA).unwrap(),
        arena.bind(quotient::SAMPLE_POINTS).unwrap(),
        arena.bind(quotient::FIRST_TERMS).unwrap(),
        destinations,
        arena.bind(quotient::TWIDDLES).unwrap(),
        slots,
        &[arena.bind(quotient::OVERFLOW).unwrap()],
    )
    .unwrap()
}

fn prepare_prepacked<'a>(
    arena: &'a DeviceArena,
    config: QuotientNumeratorWorkspaceConfig,
    slots: &QuotientNumeratorWorkspaceSlots,
    columns: &[QuotientNumeratorColumn],
    destinations: &[QuotientNumeratorDestination],
) -> PreparedQuotientNumeratorGraph<'a> {
    PreparedQuotientNumeratorGraph::prepare_staged_prepacked_single_write_candidate(
        arena,
        config,
        columns,
        arena.bind(quotient::OODS_POINTS).unwrap(),
        arena.bind(quotient::OODS_VALUES).unwrap(),
        arena.bind(quotient::ALPHA).unwrap(),
        arena.bind(quotient::SAMPLE_POINTS).unwrap(),
        arena.bind(quotient::FIRST_TERMS).unwrap(),
        destinations,
        arena.bind(quotient::TWIDDLES).unwrap(),
        slots,
        &[arena.bind(quotient::OVERFLOW).unwrap()],
    )
    .unwrap()
}

fn fill_outputs(arena: &DeviceArena, destinations: &[QuotientNumeratorDestination], byte: u8) {
    for destination in destinations {
        for coordinate in destination.coordinates {
            fill(arena, coordinate, byte);
        }
    }
}

fn assert_outputs_still_filled(
    arena: &DeviceArena,
    destinations: &[QuotientNumeratorDestination],
    byte: u8,
) {
    let word = u32::from_ne_bytes([byte; 4]);
    for destination in destinations {
        for coordinate in destination.coordinates {
            assert_eq!(
                read_words(arena, coordinate, 1usize << destination.log_size),
                vec![word; 1usize << destination.log_size]
            );
        }
    }
}
