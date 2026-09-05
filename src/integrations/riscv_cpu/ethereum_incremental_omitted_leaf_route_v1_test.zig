//! Focused gates for the engine-generic Stage101 D5 provider route body.
//!
//! The end-to-end arm needs a Metal device and a cold-opened segment; what is
//! reachable here without either is exactly what the Metal command cannot
//! afford to discover in a ten-minute product build:
//!
//!   * the whole `RouteV1(Cpu, Cpu).proveAndFreshVerify` body is analysed
//!     against the q193 Poseidon2 CPU engine by reference (every generic
//!     callee it reaches -- Stage A, the omitted core prover, the shared shard
//!     batch, the envelope, the cold verifier, the closure -- is instantiated);
//!   * the `--provider-route` dispatch parser;
//!   * the fail-closed budget, with Stage A inside the proof-core window;
//!   * the receipt's required-true / required-false matrix, driven by a
//!     synthetic but fully populated receipt;
//!   * the comptime pins against the sweep's retained request values.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const route_mod = @import("ethereum_incremental_omitted_leaf_route_v1.zig");
const execution_mod =
    @import("ethereum_candidate_degree5_provider_batch_execution_v1.zig");
const throughput =
    @import("ethereum_incremental_full_leaf_throughput_execution_v1.zig");

const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Route = route_mod.RouteV1(Engine, Engine);
const Pins = route_mod.ProviderOmissionPinsV1;

const ms = std.time.ns_per_ms;

fn digest(marker: u8) [32]u8 {
    return [_]u8{marker} ** 32;
}

fn resources(wall_ns: u64) throughput.ResourceReceiptV1 {
    return .{
        .source = .unsupported,
        .wall_ns = wall_ns,
        .leaf_count = 1,
        .ns_per_leaf = wall_ns,
        .process_cpu_ns = null,
        .average_parallelism_milli = null,
        .lifetime_peak_physical_footprint_bytes = null,
        .energy_nj = null,
        .instructions = null,
        .cycles = null,
        .unavailable_reason = "synthetic",
    };
}

fn firstArmTopology() execution_mod.TopologyReceiptV1 {
    var topology = std.mem.zeroes(execution_mod.TopologyReceiptV1);
    topology.total_call_count = route_mod.RetainedSourcePinsV1.full_call_count;
    topology.pcs_pow_bits = execution_mod.Q193_POW_BITS;
    topology.fri_query_count = execution_mod.Q193_QUERY_COUNT;
    topology.fri_log_blowup_factor = execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR;
    topology.quotient_expansion_bits = execution_mod.D5_QUOTIENT_EXPANSION_BITS;
    topology.planner_shard_log_size = 18;
    topology.shard_count = 26;
    topology.concurrent_owners = 18;
    topology.wave_count = 2;
    topology.minimum_descriptor_log_size = 17;
    topology.maximum_descriptor_log_size = 18;
    topology.committed_rows = 6_684_672;
    topology.padding_rows = 13_371;
    topology.plan_identity = digest(0x11);
    topology.resource_identity_sha256 = digest(0x12);
    topology.execution_identity_sha256 = digest(0x13);
    topology.max_canonical_proof_bytes_per_shard = 128 * 1024 * 1024;
    topology.composition_domain_scratch_concurrent_owners = 2;
    topology.composition_domain_scratch_reservation_bytes = 2_088_763_392;
    topology.controller_reserve_bytes = 8 * 1024 * 1024 * 1024;
    topology.encoded_proof_reservation_bytes = 26 * 128 * 1024 * 1024;
    return topology;
}

fn steadyTiming() route_mod.TimingV1 {
    return .{
        .runtime_init_ns = 900 * ms,
        .admission_ns = 100 * ms,
        .replay_ns = 100 * ms,
        .snapshot_ns = 10 * ms,
        .witness_ns = 400 * ms,
        .profile_ns = 400 * ms,
        .plan_ns = 200 * ms,
        .stage_a_ns = 1_100 * ms,
        .core_prove_ns = 300 * ms,
        .shard_prove_ns = 2_200 * ms,
        .encode_ns = 200 * ms,
        .core_fresh_verify_ns = 3_000 * ms,
        .shard_fresh_verify_ns = 3_600 * ms,
        .closure_ns = 1 * ms,
        .total_ns = 5_000 * ms,
    };
}

fn telemetry() route_mod.TelemetryReceiptV1 {
    return .{
        .metal_dispatch_total = 4_000,
        .cpu_fallback_total = 3,
        .resident_merkle_commits = 100,
        .poseidon_merkle_commits = 100,
        .sampled_value_dispatches = 27,
        .quotient_dispatches = 27,
        .circle_transform_dispatches = 500,
        .circle_lde_dispatches = 500,
        .fri_circle_dispatches = 27,
        .fri_line_dispatches = 600,
        .base_eligible_components = 104 + 78,
        .lookup_eligible_components = 26 + 75,
        .base_batch_dispatches = 27,
        .lookup_batch_dispatches = 27,
        .polynomial_declines = 0,
        .host_merkle_commits = 0,
        .cpu_small_merkle_commits = 0,
        .cpu_streaming_merkle_commits = 0,
        .cpu_sampled_value_evaluations = 0,
        .cpu_small_circle_interpolations = 1,
        .cpu_small_circle_evaluations = 1,
        .cpu_small_circle_ldes = 1,
        .cpu_composition_evaluations = 0,
    };
}

fn backend() route_mod.BackendReceiptV1 {
    return .{
        .aot_manifest_sha256 = digest(0x21),
        .aot_metallib_sha256 = digest(0x22),
        .aot_source_sha256 = digest(0x23),
        .aot_air_sha256 = digest(0x24),
        .aot_native_export_count = 166,
        .backend_identity_sha256 = digest(0x25),
        .platform_identity_sha256 = digest(0x26),
        .build_identity_sha256 = digest(0x27),
        .runtime_initialization_ns = 900 * ms,
        .admitted_host_placements = 3,
        .telemetry = telemetry(),
    };
}

/// A synthetic outcome that satisfies every field-level requirement.
fn outcome() route_mod.OutcomeV1 {
    const pins = route_mod.RetainedSourcePinsV1;
    return .{
        .segment_index = pins.segment_index,
        .elf_byte_count = pins.elf_byte_count,
        .elf_sha256 = pins.elf_sha256,
        .program_source_identity_sha256 = digest(0x31),
        .stwipr04_reference_byte_count = pins.reference_byte_count,
        .stwipr04_reference_sha256 = pins.reference_sha256,
        .stwipw04_payload_byte_count = pins.payload_byte_count,
        .stwipw04_payload_sha256 = pins.payload_sha256,
        .retained_source_byte_count = 1_000,
        .retained_source_sha256 = digest(0x32),
        .prepared_source_identity_sha256 = digest(0x33),
        .prepared_profile_identity_sha256 = digest(0x34),
        .program_base = pins.program_base,
        .program_end = pins.program_end,
        .declared_program_word_count = pins.declared_program_word_count,
        .committed_program_word_count = pins.committed_program_word_count,
        .program_leaf_count = pins.program_leaf_count,
        .program_call_count = pins.program_call_count,
        .program_commitment_root = 7,
        .incremental_memory_call_count = pins.incremental_memory_call_count,
        .call_count = pins.full_call_count,
        .topology = firstArmTopology(),
        .full_statement_authority_id = [_]u32{1} ** 8,
        .projected_statement_authority_id = [_]u32{2} ** 8,
        .projection_identity = digest(0x41),
        .pins_identity = Pins.identity(),
        .frame_v4_identity = digest(0x42),
        .leaf_omission_identity = digest(0x43),
        .plan_identity = digest(0x11),
        .session = digest(0x44),
        .call_list_commitment = digest(0x45),
        .manifest_identity = digest(0x46),
        .shared_relation_identity = digest(0x47),
        .relation_context_identity = digest(0x48),
        .interaction_pow = 0x1234,
        .core_artifact_byte_count = 60_000_000,
        .core_artifact_sha256 = digest(0x49),
        .core_commitments_identity = digest(0x4a),
        .prover_residual = .{ 1, 2, 3, 4 },
        .fresh_residual = .{ 1, 2, 3, 4 },
        .closure_identity = digest(0x4b),
        .strategy_identity = digest(0x4c),
        .shard_count = 26,
        .ordered_shard_proof_identity_sha256 = digest(0x4d),
        .ordered_fresh_identity_sha256 = digest(0x4e),
        .total_canonical_shard_bytes = 19_000_000,
        .air_program_identity = digest(0x4f),
        .execution_profile_identity = digest(0x50),
        .core_plus_providers_closed = true,
        .closed_sum_is_zero = true,
        .residuals_equal = true,
        .cpu_fresh_verified = true,
        .producer_proofs_destroyed_before_cpu_decode = true,
        .shared_context_verified_count = 26,
        .plan_rebuilt_from_pins_matches_decoded = true,
        .manifest_identity_equal_across_engines = true,
        .stage_a_transactions_validated_authority = true,
        .recursive_admissible = false,
        .production_eligible = false,
        .diagnostic_cancellation_ran = false,
        .legacy_full_corpus_validations_producer = 1,
        .legacy_full_corpus_validations_verifier = 1,
        .timing = steadyTiming(),
        .plan_resources = resources(200 * ms),
        .stage_a_resources = resources(1_100 * ms),
        .core_prove_resources = resources(300 * ms),
        .shard_prove_resources = resources(2_200 * ms),
        .encode_resources = resources(200 * ms),
        .core_fresh_verify_resources = resources(3_000 * ms),
        .shard_fresh_verify_resources = resources(3_600 * ms),
        .closure_resources = resources(1 * ms),
        .total_resources = resources(12_000 * ms),
    };
}

fn receipt() route_mod.ReceiptV1 {
    var result = route_mod.ReceiptV1.init(outcome(), backend(), .{});
    // Tests run in Debug; the receipt pins ReleaseFast like the sweep.
    result.build_mode = "ReleaseFast";
    return result;
}

test "Stage101 D5 route body instantiates on the q193 CPU engine" {
    // Referencing the generic body forces full semantic analysis of every
    // engine-typed callee it reaches; nothing is proved here.
    _ = &Route.proveAndFreshVerify;
    _ = &route_mod.publishReceiptThenValidateBudget;
    _ = &route_mod.sealReceiptAlloc;
    try std.testing.expect(Route.Producer == Engine);
    try std.testing.expect(Route.Verifier == route_mod.CpuVerifierEngine);
    try std.testing.expect(!route_mod.PRODUCTION_ACTIVE);
    try std.testing.expect(!route_mod.COMPLETE_LEAF_PROOF);
    try std.testing.expect(!route_mod.RECURSIVE_CAPTURE_AVAILABLE);
    try std.testing.expectEqual(@as(usize, 0), route_mod.known_red_baselines.len);
}

test "Stage101 D5 route strips only its own flag and rejects unknown route values" {
    const allocator = std.testing.allocator;
    const base = [_][]const u8{
        "--retained-materialization-result", "/r.json",
        "--publication-root",                "/p",
        "--segment-index",                   "1",
        "--output",                          "/o.json",
    };

    var absent = try route_mod.stripProviderRoute(allocator, &base);
    defer absent.deinit(allocator);
    try std.testing.expectEqual(route_mod.RouteSelectionV1.native, absent.route);
    try std.testing.expectEqual(base.len, absent.forwarded.len);
    for (base, absent.forwarded) |expected, actual|
        try std.testing.expectEqualStrings(expected, actual);

    const native = base ++ [_][]const u8{ "--provider-route", "native" };
    var native_parsed = try route_mod.stripProviderRoute(allocator, &native);
    defer native_parsed.deinit(allocator);
    try std.testing.expectEqual(route_mod.RouteSelectionV1.native, native_parsed.route);
    try std.testing.expectEqual(base.len, native_parsed.forwarded.len);

    const middle = [_][]const u8{
        "--retained-materialization-result", "/r.json",
        "--provider-route",                  "degree5-omit-v1",
        "--publication-root",                "/p",
        "--segment-index",                   "1",
        "--output",                          "/o.json",
    };
    var routed = try route_mod.stripProviderRoute(allocator, &middle);
    defer routed.deinit(allocator);
    try std.testing.expectEqual(
        route_mod.RouteSelectionV1.degree5_omit_v1,
        routed.route,
    );
    try std.testing.expectEqual(base.len, routed.forwarded.len);
    for (base, routed.forwarded) |expected, actual|
        try std.testing.expectEqualStrings(expected, actual);

    const unknown = base ++ [_][]const u8{ "--provider-route", "degree5-omit-v2" };
    try std.testing.expectError(
        error.InvalidStage101ProviderRoute,
        route_mod.stripProviderRoute(allocator, &unknown),
    );
    const dangling = base ++ [_][]const u8{"--provider-route"};
    try std.testing.expectError(
        error.InvalidArguments,
        route_mod.stripProviderRoute(allocator, &dangling),
    );
    const repeated = base ++ [_][]const u8{
        "--provider-route", "native",
        "--provider-route", "degree5-omit-v1",
    };
    try std.testing.expectError(
        error.DuplicateArgument,
        route_mod.stripProviderRoute(allocator, &repeated),
    );
    // A value that happens to look like a flag is still just the value.
    const flag_value = base ++ [_][]const u8{ "--provider-route", "--output" };
    try std.testing.expectError(
        error.InvalidStage101ProviderRoute,
        route_mod.stripProviderRoute(allocator, &flag_value),
    );
}

test "Stage101 D5 route budget maps stage A into the proof-core window" {
    const budget = route_mod.ProviderRouteBudgetV1{};
    try std.testing.expectEqual(@as(u64, 5 * std.time.ns_per_s), budget.total_ns);
    var exact = steadyTiming();
    try std.testing.expectEqual(@as(u64, 5_000 * ms), try exact.steadyStateTotalNs());
    try std.testing.expectEqual(@as(u64, 3_800 * ms), try exact.proofCoreWindowNs());
    try budget.validate(exact);

    // Stage A shares the 3.8 s proof-core window with plan, core and shards.
    var drift = exact;
    drift.stage_a_ns += 1;
    drift.total_ns += 1;
    try std.testing.expectError(
        error.Stage101ProviderRouteBudgetExceeded,
        budget.validate(drift),
    );
    // Moving time between Stage A and the shard prove is neutral.
    drift = exact;
    drift.stage_a_ns += 1_000 * ms;
    drift.shard_prove_ns -= 1_000 * ms;
    try budget.validate(drift);
    // The recorded total must be the steady-state sum, not a smaller number.
    drift = exact;
    drift.total_ns -= 1;
    try std.testing.expectError(
        error.Stage101ProviderRouteBudgetExceeded,
        budget.validate(drift),
    );
    drift = exact;
    drift.admission_ns += 1;
    drift.total_ns += 1;
    try std.testing.expectError(
        error.Stage101ProviderRouteBudgetExceeded,
        budget.validate(drift),
    );
    drift = exact;
    drift.encode_ns += 1;
    drift.total_ns += 1;
    try std.testing.expectError(
        error.Stage101ProviderRouteBudgetExceeded,
        budget.validate(drift),
    );
    // Fresh verification and runtime initialisation are outside the budget.
    drift = exact;
    drift.core_fresh_verify_ns = 60 * std.time.ns_per_s;
    drift.runtime_init_ns = 60 * std.time.ns_per_s;
    try budget.validate(drift);
    exact = drift;
}

test "Stage101 D5 route receipt rejects unshared relation context and non-zero closure" {
    const allocator = std.testing.allocator;
    var valid = receipt();
    try valid.validateFields();
    const encoded = try route_mod.sealReceiptAlloc(allocator, &valid);
    defer allocator.free(encoded);
    try valid.validate(allocator);
    try std.testing.expect(encoded.len > 2 and encoded[encoded.len - 1] == '\n');

    var unshared = receipt();
    unshared.shared_context_verified_count = 25;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        unshared.validateFields(),
    );
    var open = receipt();
    open.closed_sum_is_zero = false;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        open.validateFields(),
    );
    var residual = receipt();
    residual.fresh_residual[3] += 1;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        residual.validateFields(),
    );
    var eligible = receipt();
    eligible.production_eligible = true;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        eligible.validateFields(),
    );
    var admissible = receipt();
    admissible.recursive_admissible = true;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        admissible.validateFields(),
    );
    var unvalidated = receipt();
    unvalidated.stage_a_transactions_validated_authority = false;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        unvalidated.validateFields(),
    );
    var live_proofs = receipt();
    live_proofs.producer_proofs_destroyed_before_cpu_decode = false;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        live_proofs.validateFields(),
    );
    var drifted_pins = receipt();
    drifted_pins.pins_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        drifted_pins.validateFields(),
    );
    var rehashed = receipt();
    rehashed.legacy_full_corpus_validations_verifier = 2;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        rehashed.validateFields(),
    );
    var few_batches = receipt();
    few_batches.backend.telemetry.base_batch_dispatches = 25;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        few_batches.validateFields(),
    );
    var stray_fallback = receipt();
    stray_fallback.backend.telemetry.cpu_fallback_total += 1;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        stray_fallback.validateFields(),
    );
    var wrong_route = receipt();
    wrong_route.provider_route = "native";
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        wrong_route.validateFields(),
    );
    var resealed = valid;
    resealed.validation_identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidStage101ProviderRouteReceipt,
        resealed.validate(allocator),
    );
}

test "Stage101 D5 route pins equal the sweep's retained request" {
    // The sweep's retained first arm was driven from these environment values
    // (STWO_ZIG_D5_PROVIDER_*); the route freezes them at comptime.
    const total: u64 = route_mod.RetainedSourcePinsV1.full_call_count;
    const request = Pins.request(total);
    try std.testing.expectEqual(@as(u64, 6_671_301), request.logical_row_count);
    try std.testing.expectEqual(
        @as(u64, provider_authority.main_column_count),
        request.column_count,
    );
    try std.testing.expectEqual(@as(u32, 18), request.min_shard_log_size);
    try std.testing.expectEqual(@as(u32, 18), request.max_shard_log_size);
    try std.testing.expectEqual(
        execution_mod.Q193_FRI_LOG_BLOWUP_FACTOR,
        request.log_blowup_factor,
    );
    try std.testing.expect(request.retention_policy == .always);
    try std.testing.expectEqual(@as(u64, 51_539_607_552), request.host_byte_budget);
    try std.testing.expectEqual(@as(u64, 8_589_934_592), request.reserved_host_bytes);
    try std.testing.expectEqual(@as(u32, 18), request.requested_parallel_shards);
    try Pins.validateRequest(request, total);

    const execution = route_mod.pinnedExecutionRequest();
    try std.testing.expectEqual(@as(usize, 18), execution.concurrent_owners);
    try std.testing.expectEqual(@as(usize, 1), execution.engine_workers_per_owner);
    try std.testing.expectEqual(@as(u64, 51_539_607_552), execution.total_host_byte_budget);
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024 * 1024), execution.controller_reserve_bytes);
    try std.testing.expectEqual(@as(u64, 536_870_912), execution.non_column_reserve_per_owner);

    const residency = try Pins.residencyAuthority(total);
    try std.testing.expectEqual(@as(u32, 18), residency.result.shard_log_size);
    try std.testing.expectEqual(@as(u32, 18), residency.result.requested_parallel_shards);
    try std.testing.expect(!std.mem.allEqual(u8, &Pins.identity(), 0));
}
