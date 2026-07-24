//! Ignored cheap-GPU benchmark for the sealed SN3 quotient-numerator shape.
//! gpu-lab-cohesion-review: topology construction, byte identity, graph replay timing, and the
//! single JSON result stay together so a benchmark cannot silently drift from its comparator.
//! Run receipts must place this JSON beside `nvidia-smi` identity/driver/clock output,
//! `nvcc --version`, `rustc -Vv`, and `git rev-parse HEAD`; those are environment facts, not test
//! semantics, so the existing pod wrapper owns them.
//! Identity-complete records additionally set `STWO_SN3_BOUNDARY_SOURCE_PROJECTION_SHA256` and
//! `STWO_SN3_BOUNDARY_CUDA_MODULE_SHA256`; a git HEAD alone is not an artifact identity.

#[path = "support/sn3_quotient_numerator_bench.rs"]
mod sn3_quotient_numerator_bench;
#[path = "support/sn3_quotient_run_sum_ab.rs"]
mod sn3_quotient_run_sum_ab;
#[path = "support/sn3_quotient_topology_fixture.rs"]
mod sn3_quotient_topology_fixture;

use blake3::{Hash, Hasher};
use sn3_quotient_numerator_bench::{
    artifact_identity, assert_affine_pattern_sanity, assert_canonical_output,
    capture_canonical_output, input_recipe_digest, json_samples, percentile, poison_outputs,
    source_pattern_seed, upload_affine_pattern, CanonicalOutput, TWIDDLE_PATTERN_SEED,
};
use sn3_quotient_topology_fixture::load_sn3_topology_fixture;
use stwo::core::circle::CirclePoint;
use stwo::core::fields::qm31::SecureField;
use stwo_backend_cuda::{
    gpu_memory_info, quotient_numerator_staged_single_write_plan_with_overflow_capacities,
    quotient_numerator_workspace_requirements, quotient_workspace_requirements, ArenaLayout,
    ArenaSlice, ArenaSlotId, ArenaSlotSpec, CudaExecContext, CudaGraphExec, DeviceArena,
    PreparedNumeratorSchedule, PreparedQuotientGraph, PreparedQuotientNumeratorGraph,
    QuotientNumeratorColumn, QuotientNumeratorColumnSource, QuotientNumeratorColumnTopology,
    QuotientNumeratorDestination, QuotientNumeratorSourceKind, QuotientNumeratorWorkspaceConfig,
    QuotientNumeratorWorkspaceRequirements, QuotientNumeratorWorkspaceSlots,
    QuotientWorkspaceConfig, QuotientWorkspaceRequirements, QuotientWorkspaceSlots,
};

const GROUP_LOGS: [u32; 19] = [
    23, 19, 20, 6, 16, 18, 8, 7, 21, 14, 17, 11, 23, 15, 10, 4, 13, 12, 22,
];
const ELIGIBLE_LOGS: [u32; 18] = [
    19, 20, 6, 16, 18, 8, 7, 21, 14, 17, 11, 23, 15, 10, 4, 13, 12, 22,
];
const EXPECTED_SN3_TOPOLOGY_CONFIG: QuotientNumeratorWorkspaceConfig =
    QuotientNumeratorWorkspaceConfig {
        lifting_log_size: 24,
        log_blowup_factor: 1,
        max_lde_tile_words: 1 << 24,
    };
const SN3_QUOTIENT_CONFIG: QuotientWorkspaceConfig = QuotientWorkspaceConfig {
    lifting_log_size: 24,
    log_blowup_factor: 1,
};
const COEFFICIENT_COLUMNS: usize = 161;
const LEGACY_GROUP_COEFFICIENT_SOURCES: usize = 152;
const LEGACY_BATCHES: usize = 74;
const COEFFICIENT_BATCHES: usize = 71;
const TERMS: usize = 6_341;
const LEGACY_LOGICAL_OUTPUT_BYTES: u64 = 59_993_989_376;
const HYBRID_LOGICAL_OUTPUT_BYTES: u64 = 20_266_867_968;
const STAGED_PRIMARY_WORDS: usize = 536_870_912;
const STAGED_OVERFLOW_WORDS: usize = 452_984_832;
const STAGED_DESCRIPTOR_WORKSPACE_BYTES: u64 = 787_904;
const QUOTIENT_INCREMENTAL_ARENA_WORDS: usize = 104_857_792;
const QUOTIENT_INCREMENTAL_ARENA_BYTES: u64 = 419_431_168;
const EXPECTED_SN3_ARENA_BYTES: u64 = 46_133_748_992;
const FRI_INPUT_OUTPUT_BYTES: u64 = 268_435_456;
const FRI_COPY_CHUNK_WORDS: usize = 1 << 20;
const MAX_BENCHMARK_ARENA_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_WARMUPS: usize = 3;
const DEFAULT_ITERATIONS: usize = 20;
const EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3: &str =
    "ea31e3ff054c8d12d32d5b84a3d712987b31bb1fd3fb044fb27758453b49fbda";
const EXPECTED_SN3_INPUT_RECIPE_BLAKE3: &str =
    "e4c2f871c2d05b81588a5407f06cb49c7ed76834d2e363d2214bd34e7defcf31";
const EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3: &str =
    "a88aaa1f23b4c22201c9f9b1ed0aedc17bde8ababb50eae72a828a0eeab06ae9";
const INVERSE_TWIDDLE_PATTERN_SEED: u64 = 32_452_843;
const EAGER_LEGACY_POISON: u32 = 0xdead_beef;
const EAGER_HYBRID_POISON: u32 = 0xa5a5_5a5a;
const CAPTURE_LEGACY_POISON: u32 = 0x1357_9bdf;
const CAPTURE_HYBRID_POISON: u32 = 0x2468_ace0;
const POST_TIMING_LEGACY_POISON: u32 = 0x0bad_f00d;
const POST_TIMING_HYBRID_POISON: u32 = 0xc001_d00d;
const TIMED_LEGACY_POISON: u32 = 0x3141_5926;
const TIMED_HYBRID_POISON: u32 = 0x2718_2818;

const OODS_POINTS: ArenaSlotId = ArenaSlotId(100);
const OODS_VALUES: ArenaSlotId = ArenaSlotId(101);
const RANDOM_COEFFICIENT: ArenaSlotId = ArenaSlotId(102);
const SAMPLE_POINTS_OUTPUT: ArenaSlotId = ArenaSlotId(103);
const FIRST_TERMS_OUTPUT: ArenaSlotId = ArenaSlotId(104);
const TWIDDLES: ArenaSlotId = ArenaSlotId(105);
const SHARED_STAGED_PRIMARY: ArenaSlotId = ArenaSlotId(106);
const SHARED_STAGED_OVERFLOW: ArenaSlotId = ArenaSlotId(107);
const QUOTIENT_WORKSPACE_BASE: u32 = 200;
const INVERSE_TWIDDLES: ArenaSlotId = ArenaSlotId(207);
const SOURCE_BASE: u32 = 1_000;
const OUTPUT_BASE: u32 = 10_000;
const PACKED_WORKSPACE_BASE: u32 = 1;
const DIRECT_WORKSPACE_BASE: u32 = 20;

#[test]
#[ignore = "requires CUDA and the reported 42.97 GiB numerator-to-FRI-input arena"]
fn sn3_group_direct_run_sum_same_object_cuda_event_benchmark() {
    sn3_quotient_run_sum_ab::run();
}

#[test]
#[ignore = "requires CUDA and the reported 42.97 GiB numerator-to-FRI-input arena"]
fn sn3_staged_group_direct_cuda_event_benchmark() {
    let sn3 = load_sn3_topology_fixture(EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3);
    assert_sn3_shape(sn3.config, &sn3.topology, &sn3.requirements, &sn3.hybrid);
    let input_recipe_blake3 = input_recipe_digest(
        &sn3.topology,
        &sn3.requirements,
        &sn3.hybrid,
        &sn3.input_points,
    );
    let quotient_requirements =
        quotient_workspace_requirements(SN3_QUOTIENT_CONFIG, &GROUP_LOGS).unwrap();
    assert_sn3_quotient_shape(&quotient_requirements);
    let boundary_input_recipe_blake3 =
        boundary_input_recipe_digest(input_recipe_blake3, &quotient_requirements);
    assert_eq!(
        boundary_input_recipe_blake3.to_hex().as_str(),
        EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3
    );
    let staged_config = staged_config(sn3.config);
    let staged_requirements =
        quotient_numerator_workspace_requirements(staged_config, &sn3.topology).unwrap();
    let staged_plan = quotient_numerator_staged_single_write_plan_with_overflow_capacities(
        staged_config,
        &sn3.topology,
        &[STAGED_OVERFLOW_WORDS],
    )
    .unwrap();
    assert_staged_sn3_shape(&staged_requirements, &staged_plan);

    // All exact topology assertions above intentionally precede the first CUDA allocation.
    let (device_free_before_arena, device_total_bytes) = gpu_memory_info();
    let fixture = BenchmarkArena::new(&sn3.topology, &staged_requirements, &quotient_requirements);
    assert!(fixture.allocation_bytes <= MAX_BENCHMARK_ARENA_BYTES);
    assert_eq!(fixture.allocation_bytes, EXPECTED_SN3_ARENA_BYTES);
    let arena_pool = fixture.arena.context().pool_memory().unwrap();
    let (device_free_after_arena, device_total_after_arena) = gpu_memory_info();
    assert_eq!(device_total_after_arena, device_total_bytes);
    assert!(arena_pool.used_bytes >= fixture.allocation_bytes as usize);
    assert!(arena_pool.reserved_bytes >= arena_pool.used_bytes);

    let columns = fixture.columns(&sn3.topology);
    let destinations = fixture.destinations(&staged_requirements);
    // Both prepared graphs remain live for alternating replay. Their immutable
    // inputs, outputs, primary factor-32 tile, and overflow role may share
    // because one stream executes and fences every sample. Setup mutates
    // descriptors, so those stay disjoint.
    let packed = prepare(
        &fixture,
        &columns,
        &destinations,
        &fixture.packed_slots,
        staged_config,
        false,
    );
    let production = prepare(
        &fixture,
        &columns,
        &destinations,
        &fixture.direct_slots,
        staged_config,
        true,
    );
    let expected_schedule = PreparedNumeratorSchedule::StagedPackedSingleWrite {
        packed_output_rows: 25_165_264,
    };
    let expected_production_schedule = PreparedNumeratorSchedule::StagedGroupDirect {
        output_rows: 25_165_264,
    };
    assert_eq!(packed.schedule(), expected_schedule);
    assert_eq!(production.schedule(), expected_production_schedule);
    let run_sum = production
        .group_direct_run_sum_receipt()
        .expect("sealed SN3 arena must admit the production run-sum binding");
    assert_eq!((run_sum.target_group, run_sum.victim_group), (0, 12));
    assert_eq!(run_sum.scratch_words_per_coordinate, 8_388_048);
    assert_eq!(run_sum.manifest.run_count, 17);
    let run_count = u64::from(run_sum.manifest.run_count);
    let quotient_sources = production.quotient_sources();
    let quotient = PreparedQuotientGraph::prepare(
        &fixture.arena,
        SN3_QUOTIENT_CONFIG,
        &quotient_sources,
        fixture.arena.bind(TWIDDLES).unwrap(),
        fixture.arena.bind(INVERSE_TWIDDLES).unwrap(),
        &fixture.quotient_slots,
    )
    .unwrap();
    assert_eq!(
        quotient.output_evaluation().len_words(),
        quotient_requirements.output_value_words
    );

    initialize(
        &fixture,
        &sn3.topology,
        &staged_requirements,
        &quotient_requirements,
        &sn3.input_points,
        EAGER_LEGACY_POISON,
    );
    poison_fri_input(&fixture, &quotient, EAGER_LEGACY_POISON);
    packed.launch().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    let eager = capture_canonical_output(&fixture, &staged_requirements);
    let eager_fri_input = capture_fri_input(&fixture, &quotient);
    poison_outputs(&fixture, &staged_requirements, EAGER_HYBRID_POISON);
    poison_fri_input(&fixture, &quotient, EAGER_HYBRID_POISON);
    production.launch().unwrap();
    quotient.launch().unwrap();
    fixture.arena.context().sync().unwrap();
    let eager_production_blake3 =
        assert_canonical_output(&fixture, &staged_requirements, &eager, "eager production");
    let eager_production_fri_blake3 =
        assert_fri_input(&fixture, &quotient, &eager_fri_input, "eager production");
    let validated_numerator_output_bytes = staged_requirements
        .groups
        .iter()
        .map(|group| group.value_words as u64)
        .sum::<u64>()
        .checked_mul(16)
        .unwrap();
    let validated_auxiliary_output_bytes = (sn3.requirements.groups.len() as u64)
        .checked_mul(12 * 4)
        .unwrap();
    let validated_canonical_output_bytes = eager.len_bytes();
    assert_eq!(validated_numerator_output_bytes, 402_644_224);
    assert_eq!(validated_auxiliary_output_bytes, 912);
    assert_eq!(validated_canonical_output_bytes, 402_645_136);
    assert_eq!(
        validated_canonical_output_bytes,
        validated_numerator_output_bytes + validated_auxiliary_output_bytes
    );
    assert_eq!(eager_fri_input.len_bytes(), FRI_INPUT_OUTPUT_BYTES);

    let capture = fixture.arena.context().capture().unwrap();
    packed.launch().unwrap();
    quotient.launch().unwrap();
    let packed_graph = capture.finish().unwrap();
    let capture = fixture.arena.context().capture().unwrap();
    production.launch().unwrap();
    quotient.launch().unwrap();
    let production_graph = capture.finish().unwrap();
    let production_minus_packed_nodes = production_graph
        .kernel_nodes()
        .checked_sub(packed_graph.kernel_nodes())
        .unwrap();
    assert_eq!(production_minus_packed_nodes, 18 + run_count);
    let (device_free_after_graphs, device_total_after_graphs) = gpu_memory_info();
    assert_eq!(device_total_after_graphs, device_total_bytes);

    poison_outputs(&fixture, &staged_requirements, CAPTURE_LEGACY_POISON);
    poison_fri_input(&fixture, &quotient, CAPTURE_LEGACY_POISON);
    packed_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_packed_blake3 =
        assert_canonical_output(&fixture, &staged_requirements, &eager, "captured packed");
    let captured_packed_fri_blake3 =
        assert_fri_input(&fixture, &quotient, &eager_fri_input, "captured packed");
    poison_outputs(&fixture, &staged_requirements, CAPTURE_HYBRID_POISON);
    poison_fri_input(&fixture, &quotient, CAPTURE_HYBRID_POISON);
    production_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let captured_production_blake3 = assert_canonical_output(
        &fixture,
        &staged_requirements,
        &eager,
        "captured production",
    );
    let captured_production_fri_blake3 =
        assert_fri_input(&fixture, &quotient, &eager_fri_input, "captured production");

    for round in 0..DEFAULT_WARMUPS {
        if round % 2 == 0 {
            replay_cuda_ms(&packed_graph, fixture.arena.context());
            replay_cuda_ms(&production_graph, fixture.arena.context());
        } else {
            replay_cuda_ms(&production_graph, fixture.arena.context());
            replay_cuda_ms(&packed_graph, fixture.arena.context());
        }
    }

    let iterations = std::env::var("STWO_SN3_BOUNDARY_BENCH_ITERS")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("STWO_SN3_BOUNDARY_BENCH_ITERS must be an integer")
        })
        .unwrap_or(DEFAULT_ITERATIONS);
    assert!(
        iterations >= 6 && iterations % 2 == 0,
        "formal SN3 numerator-to-FRI-input A/B requires an even iteration count of at least six"
    );

    // These two replays are causally bound to full output validation. They are recorded
    // separately and excluded from the benchmark distribution because D2H validation occurs
    // between them.
    poison_outputs(&fixture, &staged_requirements, TIMED_LEGACY_POISON);
    poison_fri_input(&fixture, &quotient, TIMED_LEGACY_POISON);
    let causal_validation_packed_ms = replay_cuda_ms(&packed_graph, fixture.arena.context());
    let timed_packed_blake3 = assert_canonical_output(
        &fixture,
        &staged_requirements,
        &eager,
        "causal validation packed replay",
    );
    let timed_packed_fri_blake3 = assert_fri_input(
        &fixture,
        &quotient,
        &eager_fri_input,
        "causal validation packed replay",
    );
    poison_outputs(&fixture, &staged_requirements, TIMED_HYBRID_POISON);
    poison_fri_input(&fixture, &quotient, TIMED_HYBRID_POISON);
    let causal_validation_production_ms =
        replay_cuda_ms(&production_graph, fixture.arena.context());
    let timed_production_blake3 = assert_canonical_output(
        &fixture,
        &staged_requirements,
        &eager,
        "causal validation production replay",
    );
    let timed_production_fri_blake3 = assert_fri_input(
        &fixture,
        &quotient,
        &eager_fri_input,
        "causal validation production replay",
    );

    // Re-establish an alternating steady state after poison/D2H validation. One unrecorded
    // replay of each graph keeps the transition into measured iteration zero symmetric.
    replay_cuda_ms(&packed_graph, fixture.arena.context());
    replay_cuda_ms(&production_graph, fixture.arena.context());

    let mut packed_ms = Vec::with_capacity(iterations);
    let mut production_ms = Vec::with_capacity(iterations);
    for iteration in 0..iterations {
        if iteration % 2 == 0 {
            packed_ms.push(replay_cuda_ms(&packed_graph, fixture.arena.context()));
            production_ms.push(replay_cuda_ms(&production_graph, fixture.arena.context()));
        } else {
            production_ms.push(replay_cuda_ms(&production_graph, fixture.arena.context()));
            packed_ms.push(replay_cuda_ms(&packed_graph, fixture.arena.context()));
        }
    }

    poison_outputs(&fixture, &staged_requirements, POST_TIMING_LEGACY_POISON);
    poison_fri_input(&fixture, &quotient, POST_TIMING_LEGACY_POISON);
    packed_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_packed_blake3 =
        assert_canonical_output(&fixture, &staged_requirements, &eager, "post-timing packed");
    let post_timing_packed_fri_blake3 =
        assert_fri_input(&fixture, &quotient, &eager_fri_input, "post-timing packed");
    poison_outputs(&fixture, &staged_requirements, POST_TIMING_HYBRID_POISON);
    poison_fri_input(&fixture, &quotient, POST_TIMING_HYBRID_POISON);
    production_graph.launch(fixture.arena.context()).unwrap();
    fixture.arena.context().sync().unwrap();
    let post_timing_production_blake3 = assert_canonical_output(
        &fixture,
        &staged_requirements,
        &eager,
        "post-timing production",
    );
    let post_timing_production_fri_blake3 = assert_fri_input(
        &fixture,
        &quotient,
        &eager_fri_input,
        "post-timing production",
    );
    let artifact_identity = artifact_identity();

    let packed_p50 = percentile(&packed_ms, 50);
    let packed_p95 = percentile(&packed_ms, 95);
    let production_p50 = percentile(&production_ms, 50);
    let production_p95 = percentile(&production_ms, 95);
    println!(
        concat!(
            "{{\"schema\":\"stwo.sn3_numerator_to_fri_input_production_group_direct_dispatch.cuda_event.v2\",",
            "\"timing_scope\":\"per-replay CUDA-event device elapsed time for captured numerator then ordinary quotient-to-FRI-input graph\",",
            "\"percentile_method\":\"nearest-rank\"," ,
            "\"result_class\":\"diagnostic same-lineage packed/forced-StagedGroupDirect production-dispatch A/B; not independent mathematical truth or end-to-end planner evidence\",",
            "\"production_scope\":{{\"prepared_launch_dispatch\":true,\"production_planner_exercised\":false,\"forced_schedule\":\"StagedGroupDirect\"}},",
            "\"input_pattern\":\"input-recipe-sealed nonzero canonical-M31 affine row and twiddle patterns; bounded chunked upload\",",
            "\"twiddle_provenance\":\"synthetic affine-pattern diagnostic; not transcript-derived canonical STARK twiddles\",",
            "\"topology\":{{\"group_logs\":{:?},\"groups\":19,\"coefficient_columns\":161,",
            "\"coefficient_sources\":152,\"staged_batches\":19,\"terms\":6341,",
            "\"packed_output_rows\":25165264,\"quotient_lifting_log_size\":24,",
            "\"quotient_subdomain_log_size\":23,\"log_blowup_factor\":1}},",
            "\"bytes\":{{\"validated_numerator_output\":{}," ,
            "\"validated_auxiliary_output\":{},\"validated_canonical_output\":{}," ,
            "\"validated_fri_input_output\":{},\"incremental_quotient_workspace\":{}," ,
            "\"shared_data_disjoint_descriptors_shared_staging_arena\":{}," ,
            "\"descriptor_workspace_each\":{},\"shared_primary\":{}," ,
            "\"shared_overflow\":{}}}," ,
            "\"device_memory\":{{\"total\":{},\"free_before_arena\":{}," ,
            "\"free_after_arena\":{},\"free_after_graph_instantiation\":{},",
            "\"isolated_pool_used_after_arena\":{}," ,
            "\"isolated_pool_reserved_after_arena\":{}}}," ,
            "\"identity\":{{\"numerator_output_digest_encoding\":\"framed u32 little-endian v1\"," ,
            "\"fri_input_digest_encoding\":\"contiguous [coord0|coord1|coord2|coord3] u32 little-endian v1\"," ,
            "\"topology_fixture_blake3\":\"{}\"," ,
            "\"input_recipe_encoding\":\"sealed numerator recipe v2 plus literal ordinary quotient requirements and inverse affine twiddle recipe v2\"," ,
            "\"numerator_input_recipe_blake3\":\"{}\",\"boundary_input_recipe_blake3\":\"{}\"," ,
            "\"eager_packed_blake3\":\"{}\"," ,
            "\"eager_production_blake3\":\"{}\",\"captured_packed_blake3\":\"{}\"," ,
            "\"captured_production_blake3\":\"{}\"," ,
            "\"causal_validation_replays_excluded_from_samples\":true," ,
            "\"causal_validation_packed_blake3\":\"{}\"," ,
            "\"causal_validation_production_blake3\":\"{}\",\"post_timing_packed_blake3\":\"{}\"," ,
            "\"post_timing_production_blake3\":\"{}\",\"capture_revalidated\":true," ,
            "\"post_timing_revalidated\":true}}," ,
            "\"fri_input_identity\":{{\"eager_packed_blake3\":\"{}\",",
            "\"eager_production_blake3\":\"{}\",\"captured_packed_blake3\":\"{}\",",
            "\"captured_production_blake3\":\"{}\",\"causal_validation_packed_blake3\":\"{}\",",
            "\"causal_validation_production_blake3\":\"{}\",\"post_timing_packed_blake3\":\"{}\",",
            "\"post_timing_production_blake3\":\"{}\",\"exact_word_comparison\":true}},",
            "\"capture_topology\":{{\"packed_kernel_nodes\":{},\"production_kernel_nodes\":{},",
            "\"production_minus_packed_kernel_nodes\":{},\"run_sum_manifest_runs\":{}}},",
            "\"artifact_identity\":{{\"boundary_seal_blake3\":\"{}\"," ,
            "\"boundary_rust_source_blake3\":\"{}\"," ,
            "\"ordinary_cuda_source_blake3\":\"{}\"," ,
            "\"test_binary_blake3\":\"{}\",\"boundary_source_projection_sha256\":{}," ,
            "\"boundary_cuda_module_sha256\":{},\"cuda_build_mode\":\"{}\"," ,
            "\"expected_cuda_module_build_identity\":\"{}\"," ,
            "\"linked_cuda_module_build_identity\":\"{}\"," ,
            "\"cuda_module_target_sms\":{:?}," ,
            "\"archive_lto_covered_by_module_build_identity\":true," ,
            "\"identity_complete\":{}}}," ,
            "\"comparator\":{{\"lineage\":\"same staged LDE preparation, exact numerator ownership, and identical ordinary quotient tail; production selects the sealed native-domain run-sum binding with group-direct fallback\"," ,
            "\"numerator_comparator_source_blake3\":\"{}\"," ,
            "\"independent_truth\":false}}," ,
            "\"warmups_each\":{},\"equalization_replays_each\":1," ,
            "\"iterations_each\":{},\"minimum_iterations\":6,\"iterations_must_be_even\":true," ,
            "\"causal_validation_cuda_event_ms\":{{\"packed\":{:.6},\"production\":{:.6},",
            "\"excluded_from_samples\":true}}," ,
            "\"samples_ms\":{{\"packed\":{},\"production\":{}}}," ,
            "\"cuda_event_ms\":{{\"packed\":{{\"p50\":{:.6},\"p95\":{:.6}}}," ,
            "\"production\":{{\"p50\":{:.6},\"p95\":{:.6}}}}}," ,
            "\"speedup\":{{\"direction\":\"packed_divided_by_production\",\"p50\":{:.9},\"p95\":{:.9}}}}}"
        ),
        GROUP_LOGS,
        validated_numerator_output_bytes,
        validated_auxiliary_output_bytes,
        validated_canonical_output_bytes,
        FRI_INPUT_OUTPUT_BYTES,
        QUOTIENT_INCREMENTAL_ARENA_BYTES,
        fixture.allocation_bytes,
        STAGED_DESCRIPTOR_WORKSPACE_BYTES,
        STAGED_PRIMARY_WORDS as u64 * 4,
        STAGED_OVERFLOW_WORDS as u64 * 4,
        device_total_bytes,
        device_free_before_arena,
        device_free_after_arena,
        device_free_after_graphs,
        arena_pool.used_bytes,
        arena_pool.reserved_bytes,
        sn3.digest,
        input_recipe_blake3,
        boundary_input_recipe_blake3,
        eager.digest(),
        eager_production_blake3,
        captured_packed_blake3,
        captured_production_blake3,
        timed_packed_blake3,
        timed_production_blake3,
        post_timing_packed_blake3,
        post_timing_production_blake3,
        eager_fri_input.digest,
        eager_production_fri_blake3,
        captured_packed_fri_blake3,
        captured_production_fri_blake3,
        timed_packed_fri_blake3,
        timed_production_fri_blake3,
        post_timing_packed_fri_blake3,
        post_timing_production_fri_blake3,
        packed_graph.kernel_nodes(),
        production_graph.kernel_nodes(),
        production_minus_packed_nodes,
        run_count,
        artifact_identity.boundary_seal_blake3,
        artifact_identity.boundary_rust_source_blake3,
        artifact_identity.ordinary_cuda_source_blake3,
        artifact_identity.test_binary_blake3,
        artifact_identity.boundary_source_projection_json(),
        artifact_identity.boundary_cuda_module_json(),
        artifact_identity.cuda_build_mode,
        artifact_identity.expected_cuda_module_build_identity,
        artifact_identity.linked_cuda_module_build_identity,
        artifact_identity.cuda_module_target_sms,
        artifact_identity.is_complete(),
        artifact_identity.numerator_comparator_source_blake3,
        DEFAULT_WARMUPS,
        iterations,
        causal_validation_packed_ms,
        causal_validation_production_ms,
        json_samples(&packed_ms),
        json_samples(&production_ms),
        packed_p50,
        packed_p95,
        production_p50,
        production_p95,
        packed_p50 / production_p50,
        packed_p95 / production_p95,
    );
}

#[test]
fn sn3_input_recipe_is_deterministic_and_shape_exact() {
    assert_affine_pattern_sanity();
    let sn3 = load_sn3_topology_fixture(EXPECTED_SN3_TOPOLOGY_FIXTURE_BLAKE3);
    assert_sn3_shape(sn3.config, &sn3.topology, &sn3.requirements, &sn3.hybrid);
    let digest = input_recipe_digest(
        &sn3.topology,
        &sn3.requirements,
        &sn3.hybrid,
        &sn3.input_points,
    );
    assert_eq!(digest.to_hex().as_str(), EXPECTED_SN3_INPUT_RECIPE_BLAKE3);
    let quotient_requirements =
        quotient_workspace_requirements(SN3_QUOTIENT_CONFIG, &GROUP_LOGS).unwrap();
    assert_sn3_quotient_shape(&quotient_requirements);
    assert_eq!(
        boundary_input_recipe_digest(digest, &quotient_requirements)
            .to_hex()
            .as_str(),
        EXPECTED_SN3_BOUNDARY_INPUT_RECIPE_BLAKE3
    );
    let mut changed_points = sn3.input_points.clone();
    let distinct = changed_points
        .iter()
        .position(|point| *point != changed_points[0])
        .expect("exact SN3 fixture must contain distinct sample points");
    changed_points.swap(0, distinct);
    assert_ne!(
        input_recipe_digest(
            &sn3.topology,
            &sn3.requirements,
            &sn3.hybrid,
            &changed_points,
        ),
        digest
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
    let plan = benchmark_arena_plan(&sn3.topology, &requirements, &quotient_requirements);
    assert_eq!(plan.allocation_bytes, EXPECTED_SN3_ARENA_BYTES);
    assert_descriptor_workspaces_are_disjoint(
        &requirements,
        &plan.packed_slots,
        &plan.direct_slots,
    );
}

fn assert_sn3_shape(
    config: QuotientNumeratorWorkspaceConfig,
    topology: &[QuotientNumeratorColumnTopology],
    requirements: &QuotientNumeratorWorkspaceRequirements,
    hybrid: &stwo_backend_cuda::QuotientNumeratorHybridPlan,
) {
    assert_eq!(config, EXPECTED_SN3_TOPOLOGY_CONFIG);
    assert!(!topology.is_empty());
    assert_eq!(
        topology
            .iter()
            .filter(|column| column.source_kind == QuotientNumeratorSourceKind::Coefficients)
            .count(),
        COEFFICIENT_COLUMNS
    );
    assert_eq!(requirements.term_count, TERMS);
    assert_eq!(requirements.groups.len(), GROUP_LOGS.len());
    assert_eq!(
        requirements
            .groups
            .iter()
            .map(|group| group.log_size)
            .collect::<Vec<_>>(),
        GROUP_LOGS
    );
    assert_eq!(
        requirements.groups[0].coefficient_source_count,
        LEGACY_GROUP_COEFFICIENT_SOURCES
    );
    assert!(requirements.groups[1..]
        .iter()
        .all(|group| group.coefficient_source_count == 0));
    assert_eq!(requirements.batches.len(), LEGACY_BATCHES);
    assert_eq!(
        requirements
            .batches
            .iter()
            .map(|batch| batch.coefficient_count)
            .sum::<usize>(),
        LEGACY_GROUP_COEFFICIENT_SOURCES
    );
    assert_eq!(
        requirements
            .batches
            .iter()
            .filter(|batch| batch.coefficient_count != 0)
            .count(),
        COEFFICIENT_BATCHES
    );

    let report = hybrid.report();
    assert_eq!(report.eligible_group_count, ELIGIBLE_LOGS.len());
    assert_eq!(report.legacy_group_count, 1);
    assert_eq!(report.legacy_batch_count, LEGACY_BATCHES);
    assert_eq!(report.eligible_output_rows, 16_776_656);
    assert_eq!(report.legacy_output_rows, 8_388_608);
    assert_eq!(
        report.legacy_logical_output_bytes,
        LEGACY_LOGICAL_OUTPUT_BYTES
    );
    assert_eq!(
        report.hybrid_logical_output_bytes,
        HYBRID_LOGICAL_OUTPUT_BYTES
    );
    assert_eq!(hybrid.packed_terms().len(), 19_023);
    assert_eq!(hybrid.packed_group_offsets().len(), 168);
}

fn assert_sn3_quotient_shape(requirements: &QuotientWorkspaceRequirements) {
    assert_eq!(requirements.config, SN3_QUOTIENT_CONFIG);
    assert_eq!(requirements.subdomain_log_size, 23);
    assert_eq!(requirements.sample_count, 19);
    assert_eq!(requirements.sample_point_words, 152);
    assert_eq!(requirements.first_linear_term_words, 76);
    assert_eq!(requirements.partial_log_size_words, 19);
    assert_eq!(requirements.partial_pointer_words, 152);
    assert_eq!(requirements.coordinate_pointer_words, 8);
    assert_eq!(requirements.coefficient_size_words, 4);
    assert_eq!(requirements.subdomain_value_words, 33_554_432);
    assert_eq!(requirements.output_value_words, 67_108_864);
    assert_eq!(requirements.forward_twiddle_words, 8_388_608);
    assert_eq!(requirements.inverse_twiddle_words, 4_194_304);
    assert_eq!(
        u64::try_from(requirements.output_value_words).unwrap() * 4,
        FRI_INPUT_OUTPUT_BYTES
    );
}

fn staged_config(
    topology_config: QuotientNumeratorWorkspaceConfig,
) -> QuotientNumeratorWorkspaceConfig {
    QuotientNumeratorWorkspaceConfig {
        max_lde_tile_words: 32 * (1usize << topology_config.lifting_log_size),
        ..topology_config
    }
}

fn assert_staged_sn3_shape(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    staged: &stwo_backend_cuda::QuotientNumeratorStagedSingleWritePlan,
) {
    assert_eq!(requirements.config.max_lde_tile_words, STAGED_PRIMARY_WORDS);
    assert_eq!(requirements.batches.len(), 19);
    assert_eq!(requirements.term_count, TERMS);
    assert_eq!(
        requirements
            .groups
            .iter()
            .map(|group| group.log_size)
            .collect::<Vec<_>>(),
        GROUP_LOGS
    );
    assert_eq!(staged.requirements(), requirements);
    assert_eq!(staged.packed_output_rows(), 25_165_264);
    assert_eq!(staged.overflow_role_words(), [STAGED_OVERFLOW_WORDS]);
    let report = staged.report();
    assert_eq!(report.factor32_batch_count, 19);
    assert_eq!(report.factor32_staging_words, STAGED_PRIMARY_WORDS);
    assert_eq!(report.primary_staging_words, 526_981_024);
    assert_eq!(report.overflow_staging_words, STAGED_OVERFLOW_WORDS);
    assert_eq!(report.overflow_staging_role_count, 1);
}

struct BenchmarkArena {
    arena: DeviceArena,
    packed_slots: QuotientNumeratorWorkspaceSlots,
    direct_slots: QuotientNumeratorWorkspaceSlots,
    quotient_slots: QuotientWorkspaceSlots,
    source_ids: Vec<ArenaSlotId>,
    destination_ids: Vec<[ArenaSlotId; 4]>,
    allocation_bytes: u64,
}

struct BenchmarkArenaPlan {
    layout: ArenaLayout,
    packed_slots: QuotientNumeratorWorkspaceSlots,
    direct_slots: QuotientNumeratorWorkspaceSlots,
    quotient_slots: QuotientWorkspaceSlots,
    source_ids: Vec<ArenaSlotId>,
    destination_ids: Vec<[ArenaSlotId; 4]>,
    allocation_bytes: u64,
}

impl BenchmarkArena {
    fn new(
        topology: &[QuotientNumeratorColumnTopology],
        requirements: &QuotientNumeratorWorkspaceRequirements,
        quotient_requirements: &QuotientWorkspaceRequirements,
    ) -> Self {
        let plan = benchmark_arena_plan(topology, requirements, quotient_requirements);
        let arena = DeviceArena::new(CudaExecContext::new().unwrap(), plan.layout).unwrap();
        Self {
            arena,
            packed_slots: plan.packed_slots,
            direct_slots: plan.direct_slots,
            quotient_slots: plan.quotient_slots,
            source_ids: plan.source_ids,
            destination_ids: plan.destination_ids,
            allocation_bytes: plan.allocation_bytes,
        }
    }

    fn columns(
        &self,
        topology: &[QuotientNumeratorColumnTopology],
    ) -> Vec<QuotientNumeratorColumn> {
        topology
            .iter()
            .zip(&self.source_ids)
            .map(|(topology, &id)| QuotientNumeratorColumn {
                coefficient_log_size: topology.coefficient_log_size,
                source: match topology.source_kind {
                    QuotientNumeratorSourceKind::Evaluation => {
                        QuotientNumeratorColumnSource::Evaluation(self.arena.bind(id).unwrap())
                    }
                    QuotientNumeratorSourceKind::Coefficients => {
                        QuotientNumeratorColumnSource::Coefficients(self.arena.bind(id).unwrap())
                    }
                },
                samples: topology.samples.clone(),
            })
            .collect()
    }

    fn destinations(
        &self,
        requirements: &QuotientNumeratorWorkspaceRequirements,
    ) -> Vec<QuotientNumeratorDestination> {
        requirements
            .groups
            .iter()
            .zip(&self.destination_ids)
            .map(|(group, ids)| QuotientNumeratorDestination {
                log_size: group.log_size,
                coordinates: ids.map(|id| self.arena.bind(id).unwrap()),
            })
            .collect()
    }
}

fn benchmark_arena_plan(
    topology: &[QuotientNumeratorColumnTopology],
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient_requirements: &QuotientWorkspaceRequirements,
) -> BenchmarkArenaPlan {
    let packed_slots = workspace_slots(requirements, PACKED_WORKSPACE_BASE);
    let direct_slots = workspace_slots(requirements, DIRECT_WORKSPACE_BASE);
    let quotient_slots = quotient_workspace_slots();
    let mut specs = Vec::new();
    let mut cursor = 0usize;
    for slots in [&packed_slots, &direct_slots] {
        let workspace_start = cursor;
        for requirement in requirements.arena_slot_requirements(slots).unwrap() {
            if requirement.id == SHARED_STAGED_PRIMARY {
                continue;
            }
            push_spec(
                &mut specs,
                &mut cursor,
                requirement.id,
                requirement.len_words,
                requirement.alignment_words,
            );
        }
        assert_eq!(
            (cursor - workspace_start) as u64 * 4,
            STAGED_DESCRIPTOR_WORKSPACE_BYTES
        );
    }
    push_spec(
        &mut specs,
        &mut cursor,
        SHARED_STAGED_PRIMARY,
        STAGED_PRIMARY_WORDS,
        8,
    );
    push_spec(
        &mut specs,
        &mut cursor,
        SHARED_STAGED_OVERFLOW,
        STAGED_OVERFLOW_WORDS,
        8,
    );
    for (id, words) in [
        (OODS_POINTS, requirements.input_sample_count * 8),
        (OODS_VALUES, requirements.input_sample_count * 4),
        (RANDOM_COEFFICIENT, 4),
        (SAMPLE_POINTS_OUTPUT, requirements.groups.len() * 8),
        (FIRST_TERMS_OUTPUT, requirements.groups.len() * 4),
        (TWIDDLES, requirements.forward_twiddle_words),
    ] {
        push_spec(&mut specs, &mut cursor, id, words, 8);
    }
    let source_ids = topology
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let id = ArenaSlotId(SOURCE_BASE + index as u32);
            push_spec(&mut specs, &mut cursor, id, source_words(column), 8);
            id
        })
        .collect::<Vec<_>>();
    let destination_ids = requirements
        .groups
        .iter()
        .enumerate()
        .map(|(group, requirement)| {
            std::array::from_fn(|coordinate| {
                let id = output_id(group, coordinate);
                push_spec(&mut specs, &mut cursor, id, requirement.value_words, 8);
                id
            })
        })
        .collect::<Vec<_>>();
    let quotient_start = cursor;
    for requirement in quotient_requirements
        .arena_slot_requirements(&quotient_slots)
        .unwrap()
    {
        if requirement.id == SAMPLE_POINTS_OUTPUT || requirement.id == FIRST_TERMS_OUTPUT {
            continue;
        }
        push_spec(
            &mut specs,
            &mut cursor,
            requirement.id,
            requirement.len_words,
            requirement.alignment_words,
        );
    }
    push_spec(
        &mut specs,
        &mut cursor,
        INVERSE_TWIDDLES,
        quotient_requirements.inverse_twiddle_words,
        1,
    );
    assert_eq!(cursor - quotient_start, QUOTIENT_INCREMENTAL_ARENA_WORDS);
    let allocation_bytes = (cursor as u64).checked_mul(4).unwrap();
    assert!(allocation_bytes <= MAX_BENCHMARK_ARENA_BYTES);
    BenchmarkArenaPlan {
        layout: ArenaLayout::new(cursor, &specs).unwrap(),
        packed_slots,
        direct_slots,
        quotient_slots,
        source_ids,
        destination_ids,
        allocation_bytes,
    }
}

fn workspace_slots(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    base: u32,
) -> QuotientNumeratorWorkspaceSlots {
    let id = |offset| ArenaSlotId(base + offset);
    QuotientNumeratorWorkspaceSlots {
        runtime_terms: id(0),
        group_term_indices: id(1),
        group_offsets: id(2),
        line_coefficients: id(3),
        term_points: id(4),
        batch_terms: id(5),
        batch_group_offsets: id(6),
        batch_source_ptrs: id(7),
        output_ptrs: id(8),
        output_log_sizes: id(9),
        coefficient_ptrs: (requirements.coefficient_pointer_words != 0).then_some(id(10)),
        coefficient_sizes: (requirements.coefficient_size_words != 0).then_some(id(11)),
        coefficient_output_ptrs: (requirements.coefficient_output_pointer_words != 0)
            .then_some(id(12)),
        lde_tile: (requirements.lde_tile_words != 0).then_some(SHARED_STAGED_PRIMARY),
    }
}

fn quotient_workspace_slots() -> QuotientWorkspaceSlots {
    let id = |offset| ArenaSlotId(QUOTIENT_WORKSPACE_BASE + offset);
    QuotientWorkspaceSlots {
        sample_points: SAMPLE_POINTS_OUTPUT,
        first_linear_terms: FIRST_TERMS_OUTPUT,
        partial_log_sizes: id(0),
        partial_coordinate_ptrs: id(1),
        subdomain_coordinate_ptrs: id(2),
        output_coordinate_ptrs: id(3),
        coefficient_sizes: id(4),
        subdomain_values: id(5),
        output_values: id(6),
    }
}

fn assert_descriptor_workspaces_are_disjoint(
    requirements: &QuotientNumeratorWorkspaceRequirements,
    packed: &QuotientNumeratorWorkspaceSlots,
    direct: &QuotientNumeratorWorkspaceSlots,
) {
    assert_eq!(packed.lde_tile, Some(SHARED_STAGED_PRIMARY));
    assert_eq!(direct.lde_tile, Some(SHARED_STAGED_PRIMARY));
    let packed = requirements.arena_slot_requirements(packed).unwrap();
    let direct = requirements.arena_slot_requirements(direct).unwrap();
    assert!(packed
        .iter()
        .filter(|left| left.id != SHARED_STAGED_PRIMARY)
        .all(|left| direct
            .iter()
            .filter(|right| right.id != SHARED_STAGED_PRIMARY)
            .all(|right| left.id != right.id)));
}

fn push_spec(
    specs: &mut Vec<ArenaSlotSpec>,
    cursor: &mut usize,
    id: ArenaSlotId,
    len_words: usize,
    alignment_words: usize,
) {
    assert!(len_words != 0);
    let padding = (alignment_words - *cursor % alignment_words) % alignment_words;
    *cursor = cursor.checked_add(padding).unwrap();
    specs.push(ArenaSlotSpec {
        id,
        offset_words: *cursor,
        len_words,
        alignment_words,
    });
    *cursor = cursor.checked_add(len_words).unwrap();
}

fn source_words(column: &QuotientNumeratorColumnTopology) -> usize {
    let log_size = column.coefficient_log_size
        + u32::from(column.source_kind == QuotientNumeratorSourceKind::Evaluation);
    1usize << log_size
}

#[allow(clippy::too_many_arguments)]
fn prepare<'a>(
    fixture: &'a BenchmarkArena,
    columns: &[QuotientNumeratorColumn],
    destinations: &[QuotientNumeratorDestination],
    slots: &QuotientNumeratorWorkspaceSlots,
    config: QuotientNumeratorWorkspaceConfig,
    group_direct: bool,
) -> PreparedQuotientNumeratorGraph<'a> {
    let arguments = (
        fixture.arena.bind(OODS_POINTS).unwrap(),
        fixture.arena.bind(OODS_VALUES).unwrap(),
        fixture.arena.bind(RANDOM_COEFFICIENT).unwrap(),
        fixture.arena.bind(SAMPLE_POINTS_OUTPUT).unwrap(),
        fixture.arena.bind(FIRST_TERMS_OUTPUT).unwrap(),
        fixture.arena.bind(TWIDDLES).unwrap(),
    );
    let overflow_roles = [fixture.arena.bind(SHARED_STAGED_OVERFLOW).unwrap()];
    if group_direct {
        PreparedQuotientNumeratorGraph::prepare_staged_group_direct(
            &fixture.arena,
            config,
            columns,
            arguments.0,
            arguments.1,
            arguments.2,
            arguments.3,
            arguments.4,
            destinations,
            arguments.5,
            slots,
            &overflow_roles,
        )
        .unwrap()
    } else {
        PreparedQuotientNumeratorGraph::prepare_staged_packed_single_write(
            &fixture.arena,
            config,
            columns,
            arguments.0,
            arguments.1,
            arguments.2,
            arguments.3,
            arguments.4,
            destinations,
            arguments.5,
            slots,
            &overflow_roles,
        )
        .unwrap()
    }
}

fn replay_cuda_ms(graph: &CudaGraphExec, context: &CudaExecContext) -> f64 {
    assert!(context.begin_timing().unwrap() >= 1);
    graph.launch(context).unwrap();
    context.mark_timing().unwrap();
    context.sync().unwrap();
    f64::from(context.elapsed_timing_ms(1).unwrap()[0])
}

fn boundary_input_recipe_digest(
    numerator_recipe: Hash,
    requirements: &QuotientWorkspaceRequirements,
) -> Hash {
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3-numerator-to-fri-input.input-recipe.v2\0");
    hasher.update(numerator_recipe.as_bytes());
    hasher.update(&u64::try_from(GROUP_LOGS.len()).unwrap().to_le_bytes());
    for log_size in GROUP_LOGS {
        hasher.update(&u64::from(log_size).to_le_bytes());
    }
    let pass = requirements.combine_pass_bytes;
    let fields = [
        u64::from(requirements.config.lifting_log_size),
        u64::from(requirements.config.log_blowup_factor),
        u64::from(requirements.subdomain_log_size),
        u64::try_from(requirements.sample_count).unwrap(),
        u64::try_from(requirements.sample_point_words).unwrap(),
        u64::try_from(requirements.first_linear_term_words).unwrap(),
        u64::try_from(requirements.partial_log_size_words).unwrap(),
        u64::try_from(requirements.partial_pointer_words).unwrap(),
        u64::try_from(requirements.coordinate_pointer_words).unwrap(),
        u64::try_from(requirements.coefficient_size_words).unwrap(),
        u64::try_from(requirements.subdomain_value_words).unwrap(),
        u64::try_from(requirements.output_value_words).unwrap(),
        u64::try_from(pass.rows).unwrap(),
        u64::try_from(pass.samples).unwrap(),
        u64::try_from(pass.denominator_inversions).unwrap(),
        u64::try_from(pass.eliminated_scratch_bytes).unwrap(),
        u64::try_from(pass.eliminated_logical_traffic_bytes).unwrap(),
        u64::try_from(pass.denominator_global_passes).unwrap(),
        u64::try_from(pass.output_write_bytes).unwrap(),
        u64::try_from(requirements.forward_twiddle_words).unwrap(),
        u64::try_from(requirements.inverse_twiddle_words).unwrap(),
        u64::from(requirements.half_coset_initial_index),
        u64::from(requirements.half_coset_step_size),
        INVERSE_TWIDDLE_PATTERN_SEED,
    ];
    hasher.update(&u64::try_from(fields.len()).unwrap().to_le_bytes());
    for value in fields {
        hasher.update(&value.to_le_bytes());
    }
    hasher.finalize()
}

struct CanonicalFriInput {
    words: Vec<u32>,
    digest: Hash,
}

impl CanonicalFriInput {
    fn len_bytes(&self) -> u64 {
        u64::try_from(self.words.len()).unwrap() * 4
    }
}

fn capture_fri_input(
    fixture: &BenchmarkArena,
    quotient: &PreparedQuotientGraph<'_>,
) -> CanonicalFriInput {
    let source = quotient.output_evaluation();
    let mut words = Vec::with_capacity(source.len_words());
    let mut hasher = fri_input_hasher(source.len_words());
    for offset in (0..source.len_words()).step_by(FRI_COPY_CHUNK_WORDS) {
        let chunk = read_fri_input_chunk(&fixture.arena, source, offset);
        hash_fri_input_words(&mut hasher, &chunk);
        words.extend_from_slice(&chunk);
    }
    assert_eq!(words.len(), source.len_words());
    CanonicalFriInput {
        words,
        digest: hasher.finalize(),
    }
}

fn assert_fri_input(
    fixture: &BenchmarkArena,
    quotient: &PreparedQuotientGraph<'_>,
    expected: &CanonicalFriInput,
    label: &str,
) -> Hash {
    let source = quotient.output_evaluation();
    assert_eq!(
        source.len_words(),
        expected.words.len(),
        "{label}: FRI-input shape drift"
    );
    let mut hasher = fri_input_hasher(source.len_words());
    for offset in (0..source.len_words()).step_by(FRI_COPY_CHUNK_WORDS) {
        let actual = read_fri_input_chunk(&fixture.arena, source, offset);
        let expected_chunk = &expected.words[offset..offset + actual.len()];
        if let Some(relative_index) = actual
            .iter()
            .zip(expected_chunk)
            .position(|(actual, expected)| actual != expected)
        {
            let index = offset + relative_index;
            panic!(
                "{label}: FRI input differs at word {index}: expected {}, got {}",
                expected.words[index], actual[relative_index]
            );
        }
        hash_fri_input_words(&mut hasher, &actual);
    }
    let digest = hasher.finalize();
    assert_eq!(digest, expected.digest, "{label}: FRI-input digest drift");
    digest
}

fn poison_fri_input(fixture: &BenchmarkArena, quotient: &PreparedQuotientGraph<'_>, poison: u32) {
    let output = quotient.output_evaluation();
    unsafe {
        fixture
            .arena
            .context()
            .fill_u32_async(output.as_u32_ptr(), poison, output.len_words())
            .unwrap();
    }
    fixture.arena.context().sync().unwrap();
}

fn read_fri_input_chunk(arena: &DeviceArena, source: ArenaSlice, offset: usize) -> Vec<u32> {
    let count = FRI_COPY_CHUNK_WORDS.min(source.len_words() - offset);
    let chunk = source.checked_subslice(offset, count).unwrap();
    let mut words = vec![0u32; count];
    unsafe {
        arena
            .context()
            .memcpy_d2h_async(
                words.as_mut_ptr().cast(),
                chunk.as_void_ptr(),
                std::mem::size_of_val(&*words),
            )
            .unwrap();
    }
    arena.context().sync().unwrap();
    words
}

fn fri_input_hasher(word_count: usize) -> Hasher {
    let mut hasher = Hasher::new();
    hasher.update(b"stwo.sn3-quotient-fri-input.output.v1\0");
    hasher.update(&u64::try_from(word_count).unwrap().to_le_bytes());
    hasher
}

#[cfg(target_endian = "little")]
fn hash_fri_input_words(hasher: &mut Hasher, words: &[u32]) {
    // SAFETY: the byte view covers initialized `u32` objects and preserves
    // the required little-endian word framing on supported CUDA hosts.
    let bytes = unsafe {
        std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), std::mem::size_of_val(words))
    };
    hasher.update(bytes);
}

#[cfg(target_endian = "big")]
fn hash_fri_input_words(hasher: &mut Hasher, words: &[u32]) {
    for word in words {
        hasher.update(&word.to_le_bytes());
    }
}

fn initialize(
    fixture: &BenchmarkArena,
    topology: &[QuotientNumeratorColumnTopology],
    requirements: &QuotientNumeratorWorkspaceRequirements,
    quotient_requirements: &QuotientWorkspaceRequirements,
    points: &[CirclePoint<SecureField>],
    poison: u32,
) {
    let values = oods_values(points.len());
    upload(&fixture.arena, OODS_POINTS, &point_words(points));
    upload(&fixture.arena, OODS_VALUES, &secure_words(&values));
    upload(
        &fixture.arena,
        RANDOM_COEFFICIENT,
        &secure_words(&[random_coefficient()]),
    );
    upload_affine_pattern(
        &fixture.arena,
        TWIDDLES,
        requirements.forward_twiddle_words,
        TWIDDLE_PATTERN_SEED,
    );
    upload_affine_pattern(
        &fixture.arena,
        INVERSE_TWIDDLES,
        quotient_requirements.inverse_twiddle_words,
        INVERSE_TWIDDLE_PATTERN_SEED,
    );
    for (index, (&id, column)) in fixture.source_ids.iter().zip(topology).enumerate() {
        upload_affine_pattern(
            &fixture.arena,
            id,
            source_words(column),
            source_pattern_seed(index),
        );
    }
    poison_outputs(fixture, requirements, poison);
}

fn oods_values(count: usize) -> Vec<SecureField> {
    (0..count)
        .map(|index| {
            let value = index as u32 * 16 + 1;
            SecureField::from_u32_unchecked(value, value + 2, value + 4, value + 6)
        })
        .collect()
}

fn random_coefficient() -> SecureField {
    SecureField::from_u32_unchecked(307, 311, 313, 317)
}

fn output_id(group: usize, coordinate: usize) -> ArenaSlotId {
    ArenaSlotId(OUTPUT_BASE + (4 * group + coordinate) as u32)
}

fn upload(arena: &DeviceArena, slot: ArenaSlotId, words: &[u32]) {
    unsafe {
        arena
            .context()
            .memcpy_h2d_async(
                arena.bind(slot).unwrap().as_void_ptr(),
                words.as_ptr().cast(),
                std::mem::size_of_val(words),
            )
            .unwrap();
    }
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
