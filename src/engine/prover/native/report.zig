const std = @import("std");
const stwo = @import("stwo");
const config = @import("config.zig");
const statistics = @import("statistics.zig");

pub const SCHEMA_VERSION: u32 = 7;

pub const EnvironmentOverride = struct {
    name: []const u8,
    value: []const u8,
};

pub const Provenance = struct {
    git_commit: []const u8,
    git_dirty: bool,
    zig_version: []const u8,
    optimization: []const u8,
    target_os: []const u8,
    target_arch: []const u8,
    cpu_count: usize,
    simd_pack_width: usize,
    blake2s_requested_backend: []const u8,
    blake2s_effective_backend: []const u8,
    blake2s_simd_supported: bool,
    single_threaded: bool,
    thread_parallelism_enabled: bool,
    environment_overrides: []const EnvironmentOverride,
    complete: bool,
};

pub const Protocol = struct {
    name: config.Protocol,
    pow_bits: u32,
    log_blowup_factor: u32,
    log_last_layer_degree_bound: u32,
    n_queries: usize,
    fold_step: u32,
};

pub const WorkloadParameters = union(enum) {
    wide_fibonacci: config.WideFibonacciParameters,
    xor: config.XorParameters,
    plonk: config.PlonkParameters,
    plonk_logup: config.PlonkLogupParameters,
    state_machine: config.StateMachineParameters,
    blake: config.BlakeParameters,
    poseidon: config.PoseidonParameters,

    pub fn jsonStringify(self: WorkloadParameters, writer: anytype) !void {
        switch (self) {
            .wide_fibonacci => |parameters| try writer.write(parameters),
            .xor => |parameters| try writer.write(parameters),
            .plonk => |parameters| try writer.write(parameters),
            .plonk_logup => |parameters| try writer.write(parameters),
            .state_machine => |parameters| try writer.write(parameters),
            .blake => |parameters| try writer.write(parameters),
            .poseidon => |parameters| try writer.write(parameters),
        }
    }
};

pub const Workload = struct {
    name: []const u8,
    descriptor_sha256: []const u8,
    parameters: WorkloadParameters,
    trace_log_rows: u32,
    trace_rows: u64,
    committed_trees: u32,
    committed_columns: u64,
    committed_trace_cells: u64,
    native_unit: []const u8,
    native_units: u64,
};

pub const Session = struct {
    max_circle_log: u32,
    host_byte_budget: usize,
    retained_host_twiddle_bytes: usize,
    tower_build_count: u64,
};

pub const ResourceAdmission = struct {
    profile: config.ResourceProfile,
    accounted_bytes_per_committed_cell: u64,
    committed_cells: u64,
    accounted_bytes: u64,
    max_committed_cells: u64,
    max_accounted_bytes: u64,
};

pub const Resources = struct {
    measurement_scope: []const u8 = "verified_process_request_batch",
    source: stwo.prover.measurement.process_usage.Source,
    measured_warmups: usize,
    measured_samples: usize,
    lifetime_peak_physical_footprint_bytes: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,
    canonical_proof_bytes: usize,
    complete: bool,
    unavailable_reason: ?[]const u8,
};

pub const RuntimeAdmission = struct {
    initialized: bool,
    origin: []const u8,
    source_sha256: []const u8,
    manifest_sha256: ?[]const u8,
    metallib_sha256: ?[]const u8,
    metallib_bytes: ?u64,
    active_call_leases: u64,
    live_resident_resources: u64,
    initialization_count: u64,
    shutdown_count: u64,
    platform_identity: []const u8,
};

pub const CanonicalProof = struct {
    bytes: usize,
    sha256: []const u8,
};

pub const ProofArtifactBinding = struct {
    path: []const u8,
    sample_index: usize,
    bytes: usize,
    sha256: []const u8,
    artifact_schema_version: u32,
    upstream_commit: []const u8,
    exchange_mode: []const u8,
};

pub const ProofEvidence = struct {
    samples: []const CanonicalProof,
    verified_samples: usize,
    all_samples_byte_identical: bool,
    artifact: ?ProofArtifactBinding = null,
};

pub const BackendCounterDelta = struct {
    host_merkle_commits: u64 = 0,
    resident_merkle_commits: u64 = 0,
    metal_quotient_dispatches: u64 = 0,
    metal_sampled_value_dispatches: u64 = 0,
    metal_circle_transform_dispatches: u64 = 0,
    metal_circle_lde_dispatches: u64 = 0,
    metal_fri_circle_fold_dispatches: u64 = 0,
    metal_fri_line_fold_dispatches: u64 = 0,
    metal_fri_fold_commit_epochs: u64 = 0,
    metal_qm31_coordinate_dispatches: u64 = 0,
    metal_relation_epochs: u64 = 0,
    metal_trace_generation_dispatches: u64 = 0,
    metal_trace_generation_synchronizations: u64 = 0,
    metal_trace_generation_copybacks: u64 = 0,
    metal_composition_eval_dispatches: u64 = 0,
    riscv_base_polynomial_eligible_components: u64 = 0,
    riscv_lookup_polynomial_eligible_components: u64 = 0,
    metal_riscv_base_polynomial_batch_dispatches: u64 = 0,
    metal_riscv_lookup_polynomial_batch_dispatches: u64 = 0,
    cpu_small_merkle_commits: u64 = 0,
    cpu_streaming_merkle_commits: u64 = 0,
    cpu_sampled_value_evaluations: u64 = 0,
    cpu_small_circle_interpolations: u64 = 0,
    cpu_small_circle_evaluations: u64 = 0,
    cpu_small_circle_ldes: u64 = 0,
    cpu_composition_evaluations: u64 = 0,
    cpu_riscv_polynomial_composition_declines: u64 = 0,
    metal_commit_source_arena_aliases: u64 = 0,
    metal_commit_source_arena_memcpys: u64 = 0,
    metal_commit_source_uploads: u64 = 0,
};

pub const PipelineCacheDelta = struct {
    library_cache_hits: u64 = 0,
    library_cache_misses: u64 = 0,
    pipeline_cache_hits: u64 = 0,
    binary_archive_hits: u64 = 0,
    binary_archive_misses: u64 = 0,
    direct_compiles: u64 = 0,
    archive_populations: u64 = 0,
    archive_serializations: u64 = 0,
    pipeline_preparation_seconds: f64 = 0,
    library_preparation_seconds: f64 = 0,
    library_cache_entries: u64 = 0,
    library_cache_bytes: u64 = 0,
    library_cache_peak_entries: u64 = 0,
    library_cache_peak_bytes: u64 = 0,
    library_cache_evictions: u64 = 0,
    library_cache_rejections: u64 = 0,
    pipeline_cache_entries: u64 = 0,
    pipeline_cache_bytes: u64 = 0,
    pipeline_cache_peak_entries: u64 = 0,
    pipeline_cache_peak_bytes: u64 = 0,
    pipeline_cache_evictions: u64 = 0,
    pipeline_cache_invalidations: u64 = 0,
    pipeline_cache_rejections: u64 = 0,
    library_cache_entry_limit: u64 = 0,
    library_cache_byte_limit: u64 = 0,
    pipeline_cache_entry_limit: u64 = 0,
    pipeline_cache_byte_limit: u64 = 0,
};

pub const ArchiveStoreDelta = struct {
    archive_disk_hits: u64 = 0,
    archive_disk_misses: u64 = 0,
    archive_disk_evictions: u64 = 0,
    archive_disk_rebuilds: u64 = 0,
    archive_disk_rejections: u64 = 0,
    archive_disk_quarantines: u64 = 0,
    archive_lock_acquisitions: u64 = 0,
    archive_lock_contentions: u64 = 0,
    archive_lock_timeouts: u64 = 0,
    archive_publication_successes: u64 = 0,
    archive_publication_failures: u64 = 0,
    archive_bytes_published: u64 = 0,
    archive_bytes_evicted: u64 = 0,
    archive_persistence_bypasses: u64 = 0,
    archive_lock_wait_seconds: f64 = 0,
    archive_disk_entries: u64 = 0,
    archive_disk_bytes: u64 = 0,
    archive_disk_entry_limit: u64 = 0,
    archive_disk_byte_limit: u64 = 0,
    archive_per_entry_byte_limit: u64 = 0,
    archive_quarantine_entries: u64 = 0,
    archive_quarantine_bytes: u64 = 0,
    archive_quarantine_entry_limit: u64 = 0,
    archive_quarantine_byte_limit: u64 = 0,
};

pub const BackendTelemetryDelta = struct {
    classification: []const u8,
    metal_dispatches: u64,
    cpu_fallbacks: u64,
    counters: BackendCounterDelta,
    pipeline_cache: PipelineCacheDelta,
    archive_store: ArchiveStoreDelta,
};

pub const BackendTelemetry = struct {
    scope: []const u8 = "verified_proof_request",
    post_warmup_pipeline_cache: PipelineCacheDelta,
    post_warmup_archive_store: ArchiveStoreDelta,
    warmups: []const BackendTelemetryDelta,
    samples: []const BackendTelemetryDelta,
    total_metal_dispatches: u64,
    total_cpu_fallbacks: u64,
    valid: bool,
};

pub const Sample = struct {
    input_seconds: f64,
    prove_seconds: f64,
    proof_encode_seconds: f64,
    verify_seconds: f64,
    request_seconds: f64,
    native_mhz: f64,
    request_native_mhz: f64,
    trace_row_mhz: f64,
    request_trace_row_mhz: f64,
    committed_mcells_per_second: f64,
};

pub const StageProfile = stwo.prover.stage_profile.StageProfile;

pub const Timing = struct {
    backend_init_seconds: f64,
    warmup_request_seconds: []const f64,
    samples: []const Sample,
    stage_profiles: ?[]const StageProfile,
    input_seconds: statistics.Summary,
    prove_seconds: statistics.Summary,
    proof_encode_seconds: statistics.Summary,
    verify_seconds: statistics.Summary,
    request_seconds: statistics.Summary,
};

pub const Throughput = struct {
    headline_eligible: bool,
    headline_native_mhz: ?statistics.Summary,
    diagnostic_native_mhz: ?statistics.Summary,
    headline_request_native_mhz: ?statistics.Summary,
    diagnostic_request_native_mhz: ?statistics.Summary,
    headline_trace_row_mhz: ?statistics.Summary,
    diagnostic_trace_row_mhz: ?statistics.Summary,
    headline_request_trace_row_mhz: ?statistics.Summary,
    diagnostic_request_trace_row_mhz: ?statistics.Summary,
    headline_committed_mcells_per_second: ?statistics.Summary,
    diagnostic_committed_mcells_per_second: ?statistics.Summary,
    headline_requirements: HeadlineRequirements,
};

pub const HeadlineRequirements = struct {
    verified_unprofiled: bool,
    sampling_contract: bool,
    functional_protocol: bool,
    release_fast: bool,
    clean_complete_provenance: bool,
    thread_parallelism_enabled: bool,
    byte_identical_verified_samples: bool,
    backend_telemetry_valid: bool,
};

pub const Report = struct {
    schema_version: u32 = SCHEMA_VERSION,
    product_identity: ?config.ProductIdentity = null,
    backend: config.Backend,
    evidence_class: config.EvidenceClass,
    profiled: bool,
    provenance: Provenance,
    protocol: Protocol,
    workload: Workload,
    resource_admission: ResourceAdmission,
    resources: Resources,
    session: Session,
    runtime_admission: ?RuntimeAdmission,
    proof: ProofEvidence,
    backend_telemetry: ?BackendTelemetry,
    timing: Timing,
    throughput: Throughput,
};

pub fn encodeAlloc(allocator: std.mem.Allocator, value: Report) ![]u8 {
    if (value.product_identity == null) {
        const LegacyReport = struct {
            schema_version: u32,
            backend: config.Backend,
            evidence_class: config.EvidenceClass,
            profiled: bool,
            provenance: Provenance,
            protocol: Protocol,
            workload: Workload,
            resource_admission: ResourceAdmission,
            resources: Resources,
            session: Session,
            runtime_admission: ?RuntimeAdmission,
            proof: ProofEvidence,
            backend_telemetry: ?BackendTelemetry,
            timing: Timing,
            throughput: Throughput,
        };
        return std.json.Stringify.valueAlloc(allocator, LegacyReport{
            .schema_version = value.schema_version,
            .backend = value.backend,
            .evidence_class = value.evidence_class,
            .profiled = value.profiled,
            .provenance = value.provenance,
            .protocol = value.protocol,
            .workload = value.workload,
            .resource_admission = value.resource_admission,
            .resources = value.resources,
            .session = value.session,
            .runtime_admission = value.runtime_admission,
            .proof = value.proof,
            .backend_telemetry = value.backend_telemetry,
            .timing = value.timing,
            .throughput = value.throughput,
        }, .{});
    }
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

test "native proof report: diagnostic evidence cannot populate headline rates" {
    const summary = statistics.Summary{ .median = 2, .min = 1, .max = 3, .mad = 1 };
    var profile_stages = [_]stwo.prover.stage_profile.StageNode{.{
        .id = "main_trace_commit",
        .label = "Main trace commit",
        .seconds = 1.25,
    }};
    const profiles = [_]StageProfile{.{
        .runtime = "ReleaseFast",
        .example = "wide_fibonacci",
        .stages = &profile_stages,
    }};
    const value = Report{
        .backend = .cpu_native,
        .evidence_class = .profiled_diagnostic,
        .profiled = true,
        .provenance = .{
            .git_commit = "0123456789012345678901234567890123456789",
            .git_dirty = false,
            .zig_version = "0.15.2",
            .optimization = "ReleaseFast",
            .target_os = "macos",
            .target_arch = "aarch64",
            .cpu_count = 8,
            .simd_pack_width = 4,
            .blake2s_requested_backend = "auto",
            .blake2s_effective_backend = "simd",
            .blake2s_simd_supported = true,
            .single_threaded = false,
            .thread_parallelism_enabled = true,
            .environment_overrides = &.{},
            .complete = true,
        },
        .protocol = .{ .name = .smoke, .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 },
        .workload = .{
            .name = "wide_fibonacci",
            .descriptor_sha256 = "abc",
            .parameters = .{ .wide_fibonacci = .{ .log_n_rows = 5, .sequence_len = 8 } },
            .trace_log_rows = 5,
            .trace_rows = 32,
            .committed_trees = 2,
            .committed_columns = 8,
            .committed_trace_cells = 256,
            .native_unit = "trace_rows",
            .native_units = 32,
        },
        .resource_admission = .{
            .profile = .standard,
            .accounted_bytes_per_committed_cell = 16,
            .committed_cells = 256,
            .accounted_bytes = 4096,
            .max_committed_cells = config.resource_admission.STANDARD_MAX_COMMITTED_CELLS,
            .max_accounted_bytes = config.resource_admission.STANDARD_MAX_ACCOUNTED_BYTES,
        },
        .resources = .{
            .source = .darwin_proc_pid_rusage_v6,
            .measured_warmups = 0,
            .measured_samples = 1,
            .lifetime_peak_physical_footprint_bytes = 1 << 20,
            .energy_nj = 100,
            .instructions = 1000,
            .cycles = 500,
            .canonical_proof_bytes = 42,
            .complete = true,
            .unavailable_reason = null,
        },
        .session = .{
            .max_circle_log = 6,
            .host_byte_budget = 1 << 20,
            .retained_host_twiddle_bytes = 4096,
            .tower_build_count = 1,
        },
        .runtime_admission = null,
        .proof = .{ .samples = &.{.{ .bytes = 42, .sha256 = "def" }}, .verified_samples = 1, .all_samples_byte_identical = true },
        .backend_telemetry = null,
        .timing = .{
            .backend_init_seconds = 0,
            .warmup_request_seconds = &.{},
            .samples = &.{},
            .stage_profiles = &profiles,
            .input_seconds = summary,
            .prove_seconds = summary,
            .proof_encode_seconds = summary,
            .verify_seconds = summary,
            .request_seconds = summary,
        },
        .throughput = .{
            .headline_eligible = false,
            .headline_native_mhz = null,
            .diagnostic_native_mhz = summary,
            .headline_request_native_mhz = null,
            .diagnostic_request_native_mhz = summary,
            .headline_trace_row_mhz = null,
            .diagnostic_trace_row_mhz = summary,
            .headline_request_trace_row_mhz = null,
            .diagnostic_request_trace_row_mhz = summary,
            .headline_committed_mcells_per_second = null,
            .diagnostic_committed_mcells_per_second = summary,
            .headline_requirements = .{
                .verified_unprofiled = false,
                .sampling_contract = true,
                .functional_protocol = true,
                .release_fast = true,
                .clean_complete_provenance = true,
                .thread_parallelism_enabled = true,
                .byte_identical_verified_samples = true,
                .backend_telemetry_valid = true,
            },
        },
    };
    const encoded = try encodeAlloc(std.testing.allocator, value);
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expect(object.get("product_identity") == null);
    try std.testing.expectEqualStrings("profiled_diagnostic", object.get("evidence_class").?.string);
    const throughput = object.get("throughput").?.object;
    try std.testing.expect(throughput.get("headline_native_mhz").? == .null);
    try std.testing.expect(throughput.get("diagnostic_native_mhz").? == .object);
    try std.testing.expect(object.get("backend_telemetry").? == .null);
    try std.testing.expect(object.get("proof").?.object.get("artifact").? == .null);
    try std.testing.expectEqual(@as(usize, 1), object.get("timing").?.object.get("stage_profiles").?.array.items.len);
    const session = object.get("session").?.object;
    try std.testing.expectEqual(@as(usize, 4), session.count());
    try std.testing.expectEqual(@as(i64, 6), session.get("max_circle_log").?.integer);
    try std.testing.expectEqual(@as(i64, 1 << 20), session.get("host_byte_budget").?.integer);
    try std.testing.expectEqual(@as(i64, 4096), session.get("retained_host_twiddle_bytes").?.integer);
    try std.testing.expectEqual(@as(i64, 1), session.get("tower_build_count").?.integer);
    try std.testing.expect(object.get("runtime_admission").? == .null);
    const resources = object.get("resources").?.object;
    try std.testing.expectEqualStrings(
        "verified_process_request_batch",
        resources.get("measurement_scope").?.string,
    );
    try std.testing.expectEqual(@as(i64, 42), resources.get("canonical_proof_bytes").?.integer);
    try std.testing.expect(resources.get("complete").?.bool);
}

test "native proof report: authenticated runtime identity is explicit" {
    const identity = RuntimeAdmission{
        .initialized = true,
        .origin = "authenticated_core_aot",
        .source_sha256 = "11" ** 32,
        .manifest_sha256 = "22" ** 32,
        .metallib_sha256 = "33" ** 32,
        .metallib_bytes = 4096,
        .active_call_leases = 0,
        .live_resident_resources = 0,
        .initialization_count = 1,
        .shutdown_count = 0,
        .platform_identity = "runtime-v1|registry=0000000000000001|architecture=Apple M1|os-version=26.5|os-build=25F70",
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, identity, .{});
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(
        "authenticated_core_aot",
        object.get("origin").?.string,
    );
    try std.testing.expectEqualStrings("22" ** 32, object.get("manifest_sha256").?.string);
    try std.testing.expectEqual(@as(i64, 4096), object.get("metallib_bytes").?.integer);
}

test "native proof report: proof artifact binds sample zero" {
    const evidence = ProofEvidence{
        .samples = &.{.{ .bytes = 42, .sha256 = "abc" }},
        .verified_samples = 1,
        .all_samples_byte_identical = true,
        .artifact = .{
            .path = "/tmp/proof.json",
            .sample_index = 0,
            .bytes = 42,
            .sha256 = "abc",
            .artifact_schema_version = 1,
            .upstream_commit = "pinned",
            .exchange_mode = "proof_exchange_json_wire_v1",
        },
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, evidence, .{});
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const artifact = parsed.value.object.get("artifact").?.object;
    try std.testing.expectEqual(@as(i64, 0), artifact.get("sample_index").?.integer);
    try std.testing.expectEqualStrings("/tmp/proof.json", artifact.get("path").?.string);
    try std.testing.expectEqualStrings("abc", artifact.get("sha256").?.string);
}

test "native proof report: Metal telemetry includes post-warmup cache evidence" {
    const value = BackendTelemetry{
        .post_warmup_pipeline_cache = .{
            .library_cache_hits = 2,
            .direct_compiles = 1,
            .pipeline_preparation_seconds = 0.125,
            .library_preparation_seconds = 0.25,
            .library_cache_entries = 2,
            .library_cache_peak_entries = 3,
            .library_cache_entry_limit = 8,
            .library_cache_byte_limit = 64 * 1024 * 1024,
            .pipeline_cache_entry_limit = 64,
            .pipeline_cache_byte_limit = 16 * 1024 * 1024,
        },
        .post_warmup_archive_store = .{
            .archive_disk_hits = 1,
            .archive_disk_entries = 2,
            .archive_disk_entry_limit = 128,
            .archive_disk_byte_limit = 512 * 1024 * 1024,
            .archive_per_entry_byte_limit = 128 * 1024 * 1024,
            .archive_quarantine_entry_limit = 8,
            .archive_quarantine_byte_limit = 64 * 1024 * 1024,
        },
        .warmups = &.{},
        .samples = &.{},
        .total_metal_dispatches = 0,
        .total_cpu_fallbacks = 0,
        .valid = true,
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, value, .{});
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    const cache = parsed.value.object.get("post_warmup_pipeline_cache").?.object;
    try std.testing.expectEqual(@as(i64, 1), cache.get("direct_compiles").?.integer);
    try std.testing.expectEqual(@as(f64, 0.25), cache.get("library_preparation_seconds").?.float);
    try std.testing.expectEqual(@as(i64, 2), cache.get("library_cache_entries").?.integer);
    try std.testing.expectEqual(@as(i64, 8), cache.get("library_cache_entry_limit").?.integer);
    const archive = parsed.value.object.get("post_warmup_archive_store").?.object;
    try std.testing.expectEqual(@as(i64, 1), archive.get("archive_disk_hits").?.integer);
    try std.testing.expectEqual(@as(i64, 128), archive.get("archive_disk_entry_limit").?.integer);
}
