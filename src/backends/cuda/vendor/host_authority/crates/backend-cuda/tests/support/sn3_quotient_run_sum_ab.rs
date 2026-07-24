//! Same-prepared-object SN3 promotion gate for the native-domain run sum.
//!
//! This stays a child of the sealed boundary benchmark so it reuses one exact
//! fixture, its complete byte comparator, and the ordinary quotient-to-FRI
//! tail without copying the 1,255-line integration test.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use serde_json::json;
use stwo_backend_cuda::QuotientNumeratorStagedSource;

use super::*;

const SCHEMA: &str = "stwo.sn3_numerator_to_fri_input.run_sum_same_object_ab.v1";
const WARMUPS: usize = 3;
const SAMPLES: usize = 20;
const EXPECTED_DIRECT_NODES: u64 = 141;
const EXPECTED_RUN_SUM_NODES: u64 = 158;
const SEALED_A40_RETAINED_BOUNDARY_P50_MS: f64 = 335.177_948;
const SEALED_A40_RETAINED_BOUNDARY_P95_MS: f64 = 336.626_038;
const SEALED_A40_GROUP0_P50_MS: f64 = 286.365;
const THREE_X_PROJECTED_RETAINED_BOUNDARY_MS: f64 = 144.268;
const FIVE_X_PROJECTED_RETAINED_BOUNDARY_MS: f64 = 106.086;
const THREE_X_INFERRED_GROUP0_MS: f64 = 95.455;
const FIVE_X_INFERRED_GROUP0_MS: f64 = 57.273;
const ARCHIVE_LTO_ENV: Option<&str> = option_env!("STWO_CUDA_ARCHIVE_LTO");
const EXPECTED_A40_TOTAL_BYTES: u64 = 47_697_690_624;
const MINIMUM_FREE_BEFORE_ARENA_BYTES: u64 = EXPECTED_SN3_ARENA_BYTES + (1u64 << 30);
const EXPECTED_PLAN_IDENTITY: &str =
    "3a32bee348682d156f62064dd1622f23a4ec881fda64c81a0054eaa42c7464c9";
const EXPECTED_CANONICAL_NUMERATOR: &str =
    "f75d03ad1639caf198794cb42567b3e394b0c1df51ee911efe087bc5bfaa091f";
const EXPECTED_CANONICAL_FRI: &str =
    "cd24f204ec4c5acb923c839da0e8a3a5a93c67958b1e9acb96a23c9c9fa63480";
const MUTATION_SEED_XOR: u64 = 0x6a09_e667_f3bc_c909;

const EAGER_DIRECT_POISON: u32 = 0x1020_3040;
const EAGER_CANDIDATE_POISON: u32 = 0x5060_7080;
const CAPTURE_DIRECT_POISON: u32 = 0x90a0_b0c0;
const CAPTURE_CANDIDATE_POISON: u32 = 0xd0e0_f001;
const MUTATION_DIRECT_POISON: u32 = 0x1234_5678;
const MUTATION_CANDIDATE_POISON: u32 = 0x89ab_cdef;
const RESTORE_CANDIDATE_POISON: u32 = 0x0f1e_2d3c;
const RESTORE_DIRECT_POISON: u32 = 0x4b5a_6978;
const POST_TIMING_DIRECT_POISON: u32 = 0x8765_4321;
const POST_TIMING_CANDIDATE_POISON: u32 = 0xc3d2_e1f0;

#[derive(Clone, Copy)]
struct MutatedColumn {
    column: usize,
    source_index: usize,
    source_log_size: u32,
    words: usize,
}

pub(super) fn run() {
    preflight_receipt_path();
    let preflight_compute_pids = compute_process_pids();
    assert!(
        preflight_compute_pids.is_empty(),
        "formal SN3 A/B requires an idle isolated GPU, found compute PIDs {preflight_compute_pids:?}"
    );
    assert_unique_poisons();
    let sn3 = load_sn3_topology_fixture(EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3);
    assert_sn3_shape(sn3.config, &sn3.topology, &sn3.requirements, &sn3.hybrid);
    let numerator_recipe = input_recipe_digest(
        &sn3.topology,
        &sn3.requirements,
        &sn3.hybrid,
        &sn3.input_points,
    );
    assert_eq!(
        numerator_recipe.to_hex().as_str(),
        EXPECTED_SN3_INPUT_RECIPE_BLAKE3
    );

    let quotient_requirements =
        quotient_workspace_requirements(SN3_QUOTIENT_CONFIG, &GROUP_LOGS).unwrap();
    assert_sn3_quotient_shape(&quotient_requirements);
    let boundary_recipe = boundary_input_recipe_digest(numerator_recipe, &quotient_requirements);
    assert_eq!(
        boundary_recipe.to_hex().as_str(),
        EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3
    );

    let config = staged_config(sn3.config);
    let requirements = quotient_numerator_workspace_requirements(config, &sn3.topology).unwrap();
    let staged = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        config,
        &sn3.topology,
        &[STAGED_OVERFLOW_WORDS],
    )
    .unwrap();
    assert_staged_sn3_shape(&requirements, &staged);

    let (device_free_before_arena, device_total_bytes) = gpu_memory_info();
    assert_eq!(device_total_bytes, EXPECTED_A40_TOTAL_BYTES);
    assert!(
        device_free_before_arena >= MINIMUM_FREE_BEFORE_ARENA_BYTES,
        "SN3 arena preflight requires at least {MINIMUM_FREE_BEFORE_ARENA_BYTES} free bytes, got {device_free_before_arena}"
    );
    let fixture = BenchmarkArena::new(&sn3.topology, &requirements, &quotient_requirements);
    assert_eq!(fixture.allocation_bytes, EXPECTED_SN3_ARENA_BYTES);
    let arena_pool = fixture.arena.context().pool_memory().unwrap();
    let (device_free_after_arena, device_total_after_arena) = gpu_memory_info();
    assert_eq!(device_total_after_arena, device_total_bytes);
    assert!(arena_pool.used_bytes >= fixture.allocation_bytes as usize);
    assert!(arena_pool.reserved_bytes >= arena_pool.used_bytes);
    let columns = fixture.columns(&sn3.topology);
    let destinations = fixture.destinations(&requirements);
    let prepared = prepare(
        &fixture,
        &columns,
        &destinations,
        &fixture.direct_slots,
        config,
        true,
    );
    assert_eq!(
        prepared.schedule(),
        PreparedNumeratorSchedule::StagedGroupDirect {
            output_rows: 25_165_264
        }
    );
    let receipt = prepared
        .group_direct_run_sum_receipt()
        .expect("sealed SN3 group-direct object must bind the run-sum candidate");
    assert_eq!(receipt.target_group, 0);
    assert_eq!(receipt.victim_group, 12);
    assert_eq!(receipt.target_term_begin, 0);
    assert_eq!(receipt.target_term_end, 5_885);
    assert_eq!(receipt.precomputed_term_count, 5_718);
    assert_eq!(receipt.direct_term_count, 167);
    assert_eq!(receipt.manifest.run_count, 17);
    assert_eq!(receipt.manifest.direct_term_begin, 5_718);
    assert_eq!(receipt.manifest.direct_term_end, 5_885);
    assert_eq!(receipt.scratch_words_per_coordinate, 8_388_048);
    assert_eq!(receipt.margin_words_per_coordinate, [560; 4]);
    assert_eq!(receipt.baseline_row_terms, 49_366_958_080);
    assert_eq!(receipt.candidate_add_units, 5_592_751_136);
    assert_eq!(
        blake3::Hash::from_bytes(receipt.identity).to_hex().as_str(),
        EXPECTED_PLAN_IDENTITY
    );

    let quotient_sources = prepared.quotient_sources();
    let quotient = PreparedQuotientGraph::prepare(
        &fixture.arena,
        SN3_QUOTIENT_CONFIG,
        &quotient_sources,
        fixture.arena.bind(TWIDDLES).unwrap(),
        fixture.arena.bind(INVERSE_TWIDDLES).unwrap(),
        &fixture.quotient_slots,
    )
    .unwrap();

    initialize(
        &fixture,
        &sn3.topology,
        &requirements,
        &quotient_requirements,
        &sn3.input_points,
        EAGER_DIRECT_POISON,
    );
    poison_fri_input(&fixture, &quotient, EAGER_DIRECT_POISON);
    prepared.launch_group_direct_baseline().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    let canonical = capture_canonical_output(&fixture, &requirements);
    let canonical_fri = capture_fri_input(&fixture, &quotient);
    assert_exact_bytes(canonical.len_bytes(), canonical_fri.len_bytes());
    assert_eq!(
        canonical.digest().to_hex().as_str(),
        EXPECTED_CANONICAL_NUMERATOR
    );
    assert_eq!(
        canonical_fri.digest.to_hex().as_str(),
        EXPECTED_CANONICAL_FRI
    );

    poison_boundary(&fixture, &requirements, &quotient, EAGER_CANDIDATE_POISON);
    prepared.launch().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    let eager_candidate = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "eager run-sum",
    );

    let capture = fixture.arena.context().capture().unwrap();
    prepared.launch_group_direct_baseline().unwrap();
    quotient.launch().unwrap();
    let direct_graph = capture.finish().unwrap();
    let capture = fixture.arena.context().capture().unwrap();
    prepared.launch().unwrap();
    quotient.launch().unwrap();
    let candidate_graph = capture.finish().unwrap();
    assert_eq!(direct_graph.kernel_nodes(), EXPECTED_DIRECT_NODES);
    assert_eq!(candidate_graph.kernel_nodes(), EXPECTED_RUN_SUM_NODES);
    assert_eq!(
        candidate_graph.kernel_nodes() - direct_graph.kernel_nodes(),
        u64::from(receipt.manifest.run_count)
    );
    let (device_free_after_graphs, device_total_after_graphs) = gpu_memory_info();
    assert_eq!(device_total_after_graphs, device_total_bytes);

    poison_boundary(&fixture, &requirements, &quotient, CAPTURE_DIRECT_POISON);
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_direct = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "captured direct",
    );
    poison_boundary(&fixture, &requirements, &quotient, CAPTURE_CANDIDATE_POISON);
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_candidate = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "captured run-sum",
    );

    let (evaluation, coefficient) = mutation_columns(&staged, &sn3.topology, &receipt);
    mutate_inputs(&fixture, &sn3.topology, evaluation, coefficient);
    poison_boundary(&fixture, &requirements, &quotient, MUTATION_DIRECT_POISON);
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let mutated = capture_canonical_output(&fixture, &requirements);
    let mutated_fri = capture_fri_input(&fixture, &quotient);
    assert_ne!(mutated.digest(), canonical.digest());
    assert_ne!(mutated_fri.digest, canonical_fri.digest);

    poison_boundary(
        &fixture,
        &requirements,
        &quotient,
        MUTATION_CANDIDATE_POISON,
    );
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let mutation_candidate = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &mutated,
        &mutated_fri,
        "captured run-sum after source and coefficient mutation",
    );

    restore_inputs(&fixture, &sn3.topology, evaluation, coefficient);
    poison_boundary(&fixture, &requirements, &quotient, RESTORE_CANDIDATE_POISON);
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let restored_candidate = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "restored captured run-sum",
    );
    poison_boundary(&fixture, &requirements, &quotient, RESTORE_DIRECT_POISON);
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let restored_direct = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "restored captured direct",
    );

    for warmup in 0..WARMUPS {
        if baseline_first(warmup) {
            replay_cuda_ms(&direct_graph, fixture.arena.context());
            replay_cuda_ms(&candidate_graph, fixture.arena.context());
        } else {
            replay_cuda_ms(&candidate_graph, fixture.arena.context());
            replay_cuda_ms(&direct_graph, fixture.arena.context());
        }
    }
    let mut direct_ms = Vec::with_capacity(SAMPLES);
    let mut candidate_ms = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        if baseline_first(sample) {
            direct_ms.push(replay_cuda_ms(&direct_graph, fixture.arena.context()));
            candidate_ms.push(replay_cuda_ms(&candidate_graph, fixture.arena.context()));
        } else {
            candidate_ms.push(replay_cuda_ms(&candidate_graph, fixture.arena.context()));
            direct_ms.push(replay_cuda_ms(&direct_graph, fixture.arena.context()));
        }
    }

    poison_boundary(
        &fixture,
        &requirements,
        &quotient,
        POST_TIMING_DIRECT_POISON,
    );
    direct_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_direct = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "post-timing captured direct",
    );
    poison_boundary(
        &fixture,
        &requirements,
        &quotient,
        POST_TIMING_CANDIDATE_POISON,
    );
    candidate_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_candidate = assert_boundary(
        &fixture,
        &requirements,
        &quotient,
        &canonical,
        &canonical_fri,
        "post-timing captured run-sum",
    );

    let direct_p50 = percentile(&direct_ms, 50);
    let direct_p95 = percentile(&direct_ms, 95);
    let candidate_p50 = percentile(&candidate_ms, 50);
    let candidate_p95 = percentile(&candidate_ms, 95);
    let artifact = artifact_identity();
    let saved_p50 = direct_p50 - candidate_p50;
    let saved_p95 = direct_p95 - candidate_p95;
    let inferred_group0_p50 = SEALED_A40_GROUP0_P50_MS - saved_p50;
    let projected_retained_p50 = SEALED_A40_RETAINED_BOUNDARY_P50_MS - saved_p50;
    let projected_retained_p95 = SEALED_A40_RETAINED_BOUNDARY_P95_MS - saved_p95;
    let archive_lto_requested = ARCHIVE_LTO_ENV == Some("1");
    let projection_eligible =
        archive_lto_requested && artifact.cuda_build_mode == "cuda" && artifact.is_complete();
    let keep_candidate = candidate_p50 < direct_p50;
    let result = json!({
        "schema": SCHEMA,
        "passed": true,
        "result_class": "same-prepared-object diagnostic A/B; direct is same-lineage comparator, not independent mathematical truth",
        "timing_scope": "coefficient-backed staged numerator plus unchanged ordinary quotient-to-FRI-input, CUDA-event device elapsed",
        "same_prepared_object": true,
        "baseline": "staged_group_direct",
        "candidate": "native_domain_run_sum_group0_victim_group12",
        "device_memory": {
            "expected_a40_total_bytes": EXPECTED_A40_TOTAL_BYTES,
            "minimum_free_before_arena_bytes": MINIMUM_FREE_BEFORE_ARENA_BYTES,
            "free_before_arena_bytes": device_free_before_arena,
            "total_before_arena_bytes": device_total_bytes,
            "free_after_arena_bytes": device_free_after_arena,
            "total_after_arena_bytes": device_total_after_arena,
            "free_after_graphs_bytes": device_free_after_graphs,
            "total_after_graphs_bytes": device_total_after_graphs,
            "arena_allocation_bytes": fixture.allocation_bytes,
            "pool_used_after_arena_bytes": arena_pool.used_bytes,
            "pool_reserved_after_arena_bytes": arena_pool.reserved_bytes,
            "preflight_compute_pids": preflight_compute_pids,
        },
        "bytes": {
            "validated_numerator_and_auxiliary": canonical.len_bytes(),
            "validated_fri_input": canonical_fri.len_bytes(),
            "exact_word_comparison": true,
            "poisoned_complete_writes": true,
        },
        "plan": {
            "identity_blake3": blake3::Hash::from_bytes(receipt.identity).to_hex().to_string(),
            "target_group": receipt.target_group,
            "victim_group": receipt.victim_group,
            "run_count": receipt.manifest.run_count,
            "precomputed_terms": receipt.precomputed_term_count,
            "direct_terms": receipt.direct_term_count,
            "scratch_words_per_coordinate": receipt.scratch_words_per_coordinate,
            "margin_words_per_coordinate": receipt.margin_words_per_coordinate,
            "incremental_arena_bytes": 0,
            "baseline_row_terms": receipt.baseline_row_terms,
            "candidate_add_units": receipt.candidate_add_units,
        },
        "checks": {
            "eager_candidate_exact": true,
            "captured_direct_exact": true,
            "captured_candidate_exact": true,
            "captured_source_and_coefficient_mutation_exact": true,
            "captured_restoration_candidate_exact": true,
            "captured_restoration_direct_exact": true,
            "post_timing_direct_exact": true,
            "post_timing_candidate_exact": true,
            "same_input_distinct_poison_candidate_replays_exact": true,
            "full_numerator_and_auxiliary_bytes": canonical.len_bytes() == 402_645_136,
            "full_fri_input_bytes": canonical_fri.len_bytes() == FRI_INPUT_OUTPUT_BYTES,
        },
        "mutation": {
            "evaluation_column": column_json(evaluation),
            "coefficient_column": column_json(coefficient),
            "random_coefficient_changed": true,
            "restored_to_input_recipe": true,
        },
        "digests": {
            "canonical_numerator_blake3": canonical.digest().to_string(),
            "canonical_fri_blake3": canonical_fri.digest.to_string(),
            "eager_candidate": digest_pair_json(eager_candidate),
            "captured_direct": digest_pair_json(captured_direct),
            "captured_candidate": digest_pair_json(captured_candidate),
            "mutation_candidate": digest_pair_json(mutation_candidate),
            "restored_candidate": digest_pair_json(restored_candidate),
            "restored_direct": digest_pair_json(restored_direct),
            "post_timing_direct": digest_pair_json(post_timing_direct),
            "post_timing_candidate": digest_pair_json(post_timing_candidate),
        },
        "graph": {
            "direct_kernel_nodes": direct_graph.kernel_nodes(),
            "candidate_kernel_nodes": candidate_graph.kernel_nodes(),
            "candidate_minus_direct": candidate_graph.kernel_nodes() - direct_graph.kernel_nodes(),
            "expected_delta_from_run_count": receipt.manifest.run_count,
        },
        "timing": {
            "ordering": "AB,BA alternating",
            "warmups_each": WARMUPS,
            "samples_each": SAMPLES,
            "percentile_method": "nearest-rank",
            "direct_samples_ms": direct_ms,
            "candidate_samples_ms": candidate_ms,
            "direct": {"p50_ms": direct_p50, "p95_ms": direct_p95},
            "candidate": {"p50_ms": candidate_p50, "p95_ms": candidate_p95},
            "speedup": {"p50": direct_p50 / candidate_p50, "p95": direct_p95 / candidate_p95},
        },
        "objective_reward": {
            "class": "soft A40 decision; observed coefficient-backed deltas are primary, retained-policy values are cross-run projections",
            "threshold_behavior": "never abort timing or suppress raw samples",
            "reference": {
                "sealed_retained_boundary_p50_ms": SEALED_A40_RETAINED_BOUNDARY_P50_MS,
                "sealed_retained_boundary_p95_ms": SEALED_A40_RETAINED_BOUNDARY_P95_MS,
                "sealed_group0_p50_ms": SEALED_A40_GROUP0_P50_MS,
            },
            "observed_coefficient_backed": {
                "p50_saved_ms": saved_p50,
                "p95_saved_ms": saved_p95,
                "p50_saved_fraction": saved_p50 / direct_p50,
                "p95_saved_fraction": saved_p95 / direct_p95,
                "same_run_p50_speedup": direct_p50 / candidate_p50,
                "same_run_p95_speedup": direct_p95 / candidate_p95,
            },
            "cross_run_projection": {
                "observed": false,
                "formula": "sealed retained boundary minus same-run coefficient-backed saved milliseconds",
                "inferred_group0_p50_ms": inferred_group0_p50,
                "projected_retained_p50_ms": projected_retained_p50,
                "projected_retained_p95_ms": projected_retained_p95,
            },
            "decision": {
                "candidate": if keep_candidate { "KEEP" } else { "REJECT" },
                "retained_49_to_66_gate_required": keep_candidate,
            },
            "diagnostic_projection": {
                "observed": false,
                "eligible": projection_eligible,
                "requires": "CUDA archive-LTO request plus complete artifact identity",
                "archive_lto_requested_at_compile": archive_lto_requested,
                "cuda_build_mode": artifact.cuda_build_mode,
                "artifact_identity_complete": artifact.is_complete(),
                "boundaries": {
                    "three_x_inferred_group0_max_ms": THREE_X_INFERRED_GROUP0_MS,
                    "five_x_inferred_group0_max_ms": FIVE_X_INFERRED_GROUP0_MS,
                    "three_x_projected_retained_max_ms": THREE_X_PROJECTED_RETAINED_BOUNDARY_MS,
                    "five_x_projected_retained_max_ms": FIVE_X_PROJECTED_RETAINED_BOUNDARY_MS,
                },
                "diagnostic_thresholds_met": {
                    "three_x_projected_retained": projected_retained_p50
                        <= THREE_X_PROJECTED_RETAINED_BOUNDARY_MS,
                    "five_x_projected_retained": projected_retained_p50
                        <= FIVE_X_PROJECTED_RETAINED_BOUNDARY_MS,
                },
            },
            "formal_promotion": {
                "eligible": false,
                "reason": "formal promotion requires an observed retained 49-to-66-node A/B; this coefficient-backed 141-to-158-node run is diagnostic only",
                "passes": {
                    "three_x_projected_retained": false,
                    "five_x_projected_retained": false,
                },
            },
            "same_run_diagnostic": {
                "positive_same_run_p50": candidate_p50 < direct_p50,
                "positive_same_run_p95": candidate_p95 < direct_p95,
            },
        },
        "identity": {
            "topology_fixture_blake3": sn3.digest.to_string(),
            "numerator_input_recipe_blake3": numerator_recipe.to_string(),
            "boundary_input_recipe_blake3": boundary_recipe.to_string(),
            "boundary_seal_blake3": artifact.boundary_seal_blake3.to_string(),
            "boundary_rust_source_blake3": artifact.boundary_rust_source_blake3.to_string(),
            "boundary_source_projection_sha256": artifact.boundary_source_projection_sha256(),
            "boundary_cuda_module_sha256": artifact.boundary_cuda_module_sha256(),
            "numerator_comparator_source_blake3": artifact.numerator_comparator_source_blake3.to_string(),
            "ordinary_cuda_source_blake3": artifact.ordinary_cuda_source_blake3.to_string(),
            "test_binary_blake3": artifact.test_binary_blake3.to_string(),
            "cuda_build_mode": artifact.cuda_build_mode,
            "archive_lto_requested_at_compile": archive_lto_requested,
            "expected_cuda_module_build_identity": artifact.expected_cuda_module_build_identity.to_string(),
            "linked_cuda_module_build_identity": artifact.linked_cuda_module_build_identity.to_string(),
            "cuda_module_target_sms": artifact.cuda_module_target_sms,
            "identity_complete": artifact.is_complete(),
        },
    });
    publish(&result);
}

fn assert_exact_bytes(numerator_and_auxiliary: u64, fri: u64) {
    assert_eq!(numerator_and_auxiliary, 402_645_136);
    assert_eq!(fri, FRI_INPUT_OUTPUT_BYTES);
    assert_eq!(fri, 268_435_456);
}

fn preflight_receipt_path() {
    let Some(path) = std::env::var_os("STWO_SN3_RUN_SUM_AB_RECEIPT").map(PathBuf::from) else {
        return;
    };
    assert!(
        !path.exists(),
        "refusing to replace run-sum A/B receipt {}",
        path.display()
    );
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).unwrap();
    }
}

fn compute_process_pids() -> Vec<u32> {
    let output = Command::new("nvidia-smi")
        .args(["--query-compute-apps=pid", "--format=csv,noheader,nounits"])
        .output()
        .expect("run nvidia-smi compute-process preflight");
    assert!(
        output.status.success(),
        "nvidia-smi compute-process preflight failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("nvidia-smi compute-process output must be UTF-8")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("No running processes"))
        .map(|pid| pid.parse().expect("nvidia-smi compute PID must be numeric"))
        .collect()
}

fn gpu_memory_info() -> (u64, u64) {
    let (free, total) = stwo_backend_cuda::gpu_memory_info();
    (
        free.try_into().expect("GPU free bytes fit u64"),
        total.try_into().expect("GPU total bytes fit u64"),
    )
}

fn assert_unique_poisons() {
    let poisons = [
        EAGER_DIRECT_POISON,
        EAGER_CANDIDATE_POISON,
        CAPTURE_DIRECT_POISON,
        CAPTURE_CANDIDATE_POISON,
        MUTATION_DIRECT_POISON,
        MUTATION_CANDIDATE_POISON,
        RESTORE_CANDIDATE_POISON,
        RESTORE_DIRECT_POISON,
        POST_TIMING_DIRECT_POISON,
        POST_TIMING_CANDIDATE_POISON,
    ];
    for (index, poison) in poisons.iter().enumerate() {
        assert!(!poisons[index + 1..].contains(poison));
    }
}

fn poison_boundary(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    poison: u32,
) {
    poison_outputs(fixture, requirements, poison);
    poison_fri_input(fixture, quotient, !poison);
}

fn assert_boundary(
    fixture: &BenchmarkArena,
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient: &PreparedQuotientGraph<'_>,
    expected: &CanonicalOutput,
    expected_fri: &CanonicalFriInput,
    label: &str,
) -> (Hash, Hash) {
    (
        assert_canonical_output(fixture, requirements, expected, label),
        assert_fri_input(fixture, quotient, expected_fri, label),
    )
}

fn mutation_columns(
    staged: &stwo_backend_cuda::QuotientNumeratorStagedSingleWritePlan,
    topology: &[QuotientNumeratorColumnTopology],
    receipt: &stwo_backend_cuda::QuotientNumeratorRunSumReceipt,
) -> (MutatedColumn, MutatedColumn) {
    let mut evaluation = None;
    let mut coefficient = None;
    for entry in receipt.manifest.active_entries() {
        for term in entry.term_begin as usize..entry.term_end as usize {
            let source_index = staged.term_descriptors()[term * 3] as usize;
            let source = staged.sources()[source_index];
            let candidate = MutatedColumn {
                column: source.column(),
                source_index,
                source_log_size: entry.source_log_size,
                words: source_words(&topology[source.column()]),
            };
            let slot = match source {
                QuotientNumeratorStagedSource::Evaluation { .. } => &mut evaluation,
                QuotientNumeratorStagedSource::StagedCoefficient(_) => &mut coefficient,
            };
            if slot.map_or(true, |current: MutatedColumn| {
                candidate.words < current.words
            }) {
                *slot = Some(candidate);
            }
        }
    }
    (
        evaluation.expect("run-sum prefix must read a retained evaluation"),
        coefficient.expect("run-sum prefix must read a staged coefficient"),
    )
}

fn mutate_inputs(
    fixture: &BenchmarkArena,
    topology: &[QuotientNumeratorColumnTopology],
    evaluation: MutatedColumn,
    coefficient: MutatedColumn,
) {
    for changed in [evaluation, coefficient] {
        upload_affine_pattern(
            &fixture.arena,
            fixture.source_ids[changed.column],
            source_words(&topology[changed.column]),
            source_pattern_seed(changed.column) ^ MUTATION_SEED_XOR,
        );
    }
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[SecureField::from_u32_unchecked(331, 337, 347, 349)]),
    );
    fixture.arena.context().sync().unwrap();
}

fn restore_inputs(
    fixture: &BenchmarkArena,
    topology: &[QuotientNumeratorColumnTopology],
    evaluation: MutatedColumn,
    coefficient: MutatedColumn,
) {
    for restored in [evaluation, coefficient] {
        upload_affine_pattern(
            &fixture.arena,
            fixture.source_ids[restored.column],
            source_words(&topology[restored.column]),
            source_pattern_seed(restored.column),
        );
    }
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[random_coefficient()]),
    );
    fixture.arena.context().sync().unwrap();
}

fn baseline_first(index: usize) -> bool {
    index % 2 == 0
}

fn column_json(column: MutatedColumn) -> serde_json::Value {
    json!({
        "column": column.column,
        "source_index": column.source_index,
        "source_log_size": column.source_log_size,
        "input_words": column.words,
    })
}

fn digest_pair_json((numerator, fri): (Hash, Hash)) -> serde_json::Value {
    json!({
        "numerator_blake3": numerator.to_string(),
        "fri_blake3": fri.to_string(),
    })
}

fn publish(receipt: &serde_json::Value) {
    let bytes = serde_json::to_vec_pretty(receipt).unwrap();
    if let Some(path) = std::env::var_os("STWO_SN3_RUN_SUM_AB_RECEIPT").map(PathBuf::from) {
        assert!(
            !path.exists(),
            "refusing to replace run-sum A/B receipt {}",
            path.display()
        );
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.write_all(b"\n").unwrap();
        file.sync_all().unwrap();
        fs::rename(temporary, path).unwrap();
    }
    println!(
        "STWO_SN3_RUN_SUM_AB_RECEIPT_JSON={}",
        serde_json::to_string(receipt).unwrap()
    );
}
