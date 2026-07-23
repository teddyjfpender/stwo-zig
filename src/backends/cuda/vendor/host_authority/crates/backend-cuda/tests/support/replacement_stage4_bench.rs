//! Optional CUDA-event sweeps for both Stage-4 replacement binders.

use stwo::core::circle::SECURE_FIELD_CIRCLE_GEN;
use stwo::core::fields::qm31::SecureField;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::CpuBackend;
use stwo::prover::poly::circle::PolyOps;
use stwo_backend_cuda::{
    quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    quotient_numerator_workspace_requirements, CommitProgram, CommitWorkspaceConfig,
    DomainCooperativeProgram, PreparedQuotientNumeratorGraph, ProgressiveCommitGeometry,
    ProgressiveCommitGroupGeometry, ProgressiveNttLeafFusionMode, QuotientNumeratorWorkspaceConfig,
};

use super::replacement_stage4_common::{
    cuda_event_timings, fill, upload_words, PerformanceReceipt,
};
use super::replacement_stage4_mode_a::{
    assert_commit_preserved, coefficient_columns, coefficient_set, commit_arena, retained_outputs,
    upload_coefficients, workspace_slots, COLUMNS, GUARD, TWIDDLES,
};
use super::replacement_stage4_quotient as quotient;

pub fn benchmark_mode_a(
    lifting_log_size: u32,
    warmups: usize,
    iterations: usize,
) -> PerformanceReceipt {
    assert!(lifting_log_size >= 4);
    let config = CommitWorkspaceConfig {
        log_blowup_factor: 1,
        lifting_log_size,
        unretained_bottom_layers: 4,
        max_fused_tail_levels: 2,
    };
    let geometry = ProgressiveCommitGeometry {
        lifting_log_size,
        log_blowup_factor: 1,
        groups: vec![
            ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![lifting_log_size - 2; 15],
                retain_evaluations: true,
            },
            ProgressiveCommitGroupGeometry {
                coefficient_log_sizes: vec![lifting_log_size - 1; 18],
                retain_evaluations: true,
            },
        ],
    };
    let base = CommitProgram::compile(
        config,
        geometry,
        ProgressiveNttLeafFusionMode::Fused16,
        true,
    )
    .unwrap();
    let cooperative = DomainCooperativeProgram::compile_mode_a(&base).unwrap();
    let requirements = base.requirements();
    let slots = workspace_slots(requirements);
    let (legacy_arena, legacy_bytes) = commit_arena(requirements, &slots);
    let (candidate_arena, candidate_bytes) = commit_arena(requirements, &slots);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    let twiddle_words = twiddles
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let coefficients = coefficient_set(requirements, 0x0370_7344);
    for device in [&legacy_arena, &candidate_arena] {
        upload_words(device, device.bind(TWIDDLES).unwrap(), &twiddle_words);
        upload_coefficients(device, &coefficients);
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
    let capture = legacy_arena.context().capture().unwrap();
    legacy.launch().unwrap();
    let legacy_graph = capture.finish().unwrap();
    let capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    let baseline = cuda_event_timings(legacy_arena.context(), warmups, iterations, || {
        legacy_graph.launch(legacy_arena.context())
    });
    let replacement = cuda_event_timings(candidate_arena.context(), warmups, iterations, || {
        candidate_graph.launch(candidate_arena.context())
    });
    assert_eq!(
        legacy.read_root_at_transcript_boundary().unwrap(),
        candidate.read_root_at_transcript_boundary().unwrap()
    );
    assert_commit_preserved(&legacy_arena, &coefficients);
    assert_commit_preserved(&candidate_arena, &coefficients);
    let comparison = cooperative.comparison();
    PerformanceReceipt {
        name: format!("mode-a-commit-log{lifting_log_size}"),
        parameters: [
            ("lifting_log_size".to_owned(), u64::from(lifting_log_size)),
            ("rows".to_owned(), 1u64 << lifting_log_size),
            ("columns".to_owned(), COLUMNS as u64),
            ("first_batch_columns".to_owned(), 15),
            ("second_batch_columns".to_owned(), 18),
            (
                "baseline_state_api_calls".to_owned(),
                u64::from(comparison.current_state_api_calls),
            ),
            (
                "candidate_state_api_calls".to_owned(),
                u64::from(comparison.replacement_state_api_calls),
            ),
        ]
        .into_iter()
        .collect(),
        arena_bytes: [
            ("fused16".to_owned(), legacy_bytes),
            ("mode_a".to_owned(), candidate_bytes),
        ]
        .into_iter()
        .collect(),
        traffic_bytes: [
            (
                "fused16_leaf_owned".to_owned(),
                comparison.current_leaf_traffic.total_owned_bytes().unwrap(),
            ),
            (
                "mode_a_leaf_owned".to_owned(),
                comparison
                    .replacement_leaf_traffic
                    .total_owned_bytes()
                    .unwrap(),
            ),
            (
                "mode_a_retained_reread".to_owned(),
                comparison.retained_evaluation_reread_bytes,
            ),
        ]
        .into_iter()
        .collect(),
        loaded_functions: Vec::new(),
        baseline_label: "exact-fused16-commit-program-cuda-graph".to_owned(),
        candidate_label: "exact-domain-cooperative-mode-a-cuda-graph".to_owned(),
        baseline,
        candidate: replacement,
        speedup: baseline.median_ms / replacement.median_ms,
    }
}

pub fn benchmark_quotient(
    lifting_log_size: u32,
    warmups: usize,
    iterations: usize,
) -> PerformanceReceipt {
    let config = QuotientNumeratorWorkspaceConfig {
        lifting_log_size,
        log_blowup_factor: 2,
        max_lde_tile_words: 32 * (1usize << lifting_log_size),
    };
    let points = [
        SECURE_FIELD_CIRCLE_GEN.mul(3),
        SECURE_FIELD_CIRCLE_GEN.mul(5),
        SECURE_FIELD_CIRCLE_GEN.mul(7),
        SECURE_FIELD_CIRCLE_GEN.mul(11),
    ];
    let topology = quotient::scaled_topology(points, lifting_log_size);
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
    let slots = quotient::workspace_slots(&requirements);
    let (legacy_arena, legacy_bytes) =
        quotient::make_arena(&requirements, &slots, source_words, overflow_words);
    let (candidate_arena, candidate_bytes) =
        quotient::make_arena(&requirements, &slots, source_words, overflow_words);
    let twiddles = CpuBackend::precompute_twiddles(
        CanonicCoset::new(lifting_log_size)
            .circle_domain()
            .half_coset,
    );
    let twiddle_words = twiddles
        .twiddles
        .iter()
        .map(|value| value.0)
        .collect::<Vec<_>>();
    let sources = quotient::source_set_for_words(0x1319_8a2e, source_words);
    let values = [
        SecureField::from_u32_unchecked(2, 3, 5, 7),
        SecureField::from_u32_unchecked(11, 13, 17, 19),
        SecureField::from_u32_unchecked(23, 29, 31, 37),
        SecureField::from_u32_unchecked(41, 43, 47, 53),
        SecureField::from_u32_unchecked(59, 61, 67, 71),
    ];
    for device in [&legacy_arena, &candidate_arena] {
        upload_words(
            device,
            device.bind(quotient::OODS_POINTS).unwrap(),
            &quotient::point_words(&[points[0], points[1], points[0], points[2], points[3]]),
        );
        upload_words(
            device,
            device.bind(quotient::OODS_VALUES).unwrap(),
            &quotient::secure_words(&values),
        );
        upload_words(
            device,
            device.bind(quotient::ALPHA).unwrap(),
            &quotient::secure_words(&[SecureField::from_u32_unchecked(73, 79, 83, 89)]),
        );
        upload_words(
            device,
            device.bind(quotient::TWIDDLES).unwrap(),
            &twiddle_words,
        );
        quotient::upload_sources(device, &sources);
        fill(device, device.bind(quotient::GUARD).unwrap(), 0xa5);
        device.context().sync().unwrap();
    }
    let legacy_destinations = quotient::destinations(&legacy_arena, &requirements);
    let candidate_destinations = quotient::destinations(&candidate_arena, &requirements);
    let legacy_columns = quotient::columns(&legacy_arena, &topology);
    let candidate_columns = quotient::columns(&candidate_arena, &topology);
    let legacy = PreparedQuotientNumeratorGraph::prepare_staged_packed_single_write(
        &legacy_arena,
        config,
        &legacy_columns,
        legacy_arena.bind(quotient::OODS_POINTS).unwrap(),
        legacy_arena.bind(quotient::OODS_VALUES).unwrap(),
        legacy_arena.bind(quotient::ALPHA).unwrap(),
        legacy_arena.bind(quotient::SAMPLE_POINTS).unwrap(),
        legacy_arena.bind(quotient::FIRST_TERMS).unwrap(),
        &legacy_destinations,
        legacy_arena.bind(quotient::TWIDDLES).unwrap(),
        &slots,
        &[legacy_arena.bind(quotient::OVERFLOW).unwrap()],
    )
    .unwrap();
    let candidate = PreparedQuotientNumeratorGraph::prepare_staged_group_direct(
        &candidate_arena,
        config,
        &candidate_columns,
        candidate_arena.bind(quotient::OODS_POINTS).unwrap(),
        candidate_arena.bind(quotient::OODS_VALUES).unwrap(),
        candidate_arena.bind(quotient::ALPHA).unwrap(),
        candidate_arena.bind(quotient::SAMPLE_POINTS).unwrap(),
        candidate_arena.bind(quotient::FIRST_TERMS).unwrap(),
        &candidate_destinations,
        candidate_arena.bind(quotient::TWIDDLES).unwrap(),
        &slots,
        &[candidate_arena.bind(quotient::OVERFLOW).unwrap()],
    )
    .unwrap();
    let capture = legacy_arena.context().capture().unwrap();
    legacy.launch().unwrap();
    let legacy_graph = capture.finish().unwrap();
    let capture = candidate_arena.context().capture().unwrap();
    candidate.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    let baseline = cuda_event_timings(legacy_arena.context(), warmups, iterations, || {
        legacy_graph.launch(legacy_arena.context())
    });
    let replacement = cuda_event_timings(candidate_arena.context(), warmups, iterations, || {
        candidate_graph.launch(candidate_arena.context())
    });
    assert_eq!(
        quotient::raw_snapshot(&legacy_arena, &requirements, &legacy_destinations),
        quotient::raw_snapshot(&candidate_arena, &requirements, &candidate_destinations)
    );
    quotient::assert_preserved(&legacy_arena, &sources);
    quotient::assert_preserved(&candidate_arena, &sources);
    let report = plan.report();
    PerformanceReceipt {
        name: format!("group-direct-quotient-log{lifting_log_size}"),
        parameters: [
            ("lifting_log_size".to_owned(), u64::from(lifting_log_size)),
            ("groups".to_owned(), requirements.groups.len() as u64),
            ("terms".to_owned(), requirements.term_count as u64),
            ("packed_output_rows".to_owned(), plan.packed_output_rows()),
            ("output_rows".to_owned(), report.output_rows as u64),
        ]
        .into_iter()
        .collect(),
        arena_bytes: [
            ("legacy".to_owned(), legacy_bytes),
            ("candidate".to_owned(), candidate_bytes),
        ]
        .into_iter()
        .collect(),
        traffic_bytes: [
            (
                "legacy_logical_output".to_owned(),
                report.factor32_logical_output_bytes,
            ),
            (
                "candidate_logical_output".to_owned(),
                report.candidate_logical_output_bytes,
            ),
        ]
        .into_iter()
        .collect(),
        loaded_functions: Vec::new(),
        baseline_label: "staged-packed-single-write-cuda-graph".to_owned(),
        candidate_label: "staged-group-direct-cuda-graph".to_owned(),
        baseline,
        candidate: replacement,
        speedup: baseline.median_ms / replacement.median_ms,
    }
}
