const std = @import("std");
const builtin = @import("builtin");
const stwo = @import("stwo");
pub const config = @import("config.zig");
const examples = @import("examples.zig");
const report_mod = @import("report.zig");
const provenance = @import("runner/provenance.zig");
const telemetry = @import("runner/telemetry.zig");
const statistics = @import("statistics.zig");

const examples_artifact = stwo.interop.examples_artifact;
const proof_wire = stwo.interop.proof_wire;
const stage_profile = stwo.prover.stage_profile;
const blake2_hash = stwo.core.vcs.blake2_hash;
const M31_PACK_WIDTH = stwo.core.fields.m31.PACK_WIDTH;
const HOST_TWIDDLE_BUDGET_BYTES: usize = 256 * 1024 * 1024;
const process_usage = stwo.prover.measurement.process_usage;

fn SampleOutcome(comptime Statement: type) type {
    return struct {
        timing: report_mod.Sample,
        statement: Statement,
        canonical_proof: []u8,
        stage_profile: ?report_mod.StageProfile,

        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            allocator.free(self.canonical_proof);
            if (self.stage_profile) |*profile| profile.deinit(allocator);
            self.* = undefined;
        }
    };
}

fn GatedSampleOutcome(comptime Statement: type) type {
    return struct {
        sample: SampleOutcome(Statement),
        telemetry: ?report_mod.BackendTelemetryDelta,
    };
}

pub fn main(comptime Engine: type, comptime backend: config.Backend) !void {
    return mainWithProduct(Engine, backend, null);
}

pub fn mainWithProduct(
    comptime Engine: type,
    comptime backend: config.Backend,
    product_identity: ?config.ProductIdentity,
) !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);

    const parsed = parse: {
        const result = config.parseArgs(backend, process_args[1..]) catch |err| {
            try config.writeUsage(std.fs.File.stderr().deprecatedWriter(), backend);
            return err;
        };
        break :parse result;
    };
    switch (parsed) {
        .help => return config.writeUsage(std.fs.File.stdout().deprecatedWriter(), backend),
        .run => |parsed_args| {
            var args = parsed_args;
            args.product_identity = product_identity;
            const encoded = try run(Engine, backend, allocator, args);
            defer allocator.free(encoded);
            const stdout = std.fs.File.stdout().deprecatedWriter();
            try stdout.writeAll(encoded);
            try stdout.writeByte('\n');
        },
    }
}

pub fn run(
    comptime Engine: type,
    comptime backend: config.Backend,
    allocator: std.mem.Allocator,
    args: config.Args,
) ![]u8 {
    blake2_hash.setDefaultBackendMode(switch (args.blake2_backend) {
        .auto => .auto,
        .scalar => .scalar,
        .simd => .simd,
    });
    return switch (args.workload()) {
        .wide_fibonacci => |parameters| executeExample(
            Engine,
            backend,
            examples.WideFibonacciSpec,
            allocator,
            args,
            args.workload(),
            examples.WideFibonacciSpec.request(parameters),
        ),
        .xor => |parameters| executeExample(
            Engine,
            backend,
            examples.XorSpec,
            allocator,
            args,
            args.workload(),
            examples.XorSpec.request(parameters),
        ),
        .plonk => |parameters| executeExample(
            Engine,
            backend,
            examples.PlonkSpec,
            allocator,
            args,
            args.workload(),
            examples.PlonkSpec.request(parameters),
        ),
        .plonk_logup => |parameters| executeExample(
            Engine,
            backend,
            examples.PlonkLogupSpec,
            allocator,
            args,
            args.workload(),
            examples.PlonkLogupSpec.request(parameters),
        ),
        .state_machine => |parameters| executeExample(
            Engine,
            backend,
            examples.StateMachineSpec,
            allocator,
            args,
            args.workload(),
            examples.StateMachineSpec.request(parameters),
        ),
        .blake => |parameters| executeExample(
            Engine,
            backend,
            examples.BlakeSpec,
            allocator,
            args,
            args.workload(),
            examples.BlakeSpec.request(parameters),
        ),
        .poseidon => |parameters| executeExample(
            Engine,
            backend,
            examples.PoseidonSpec,
            allocator,
            args,
            args.workload(),
            examples.PoseidonSpec.request(parameters),
        ),
    };
}

fn executeExample(
    comptime Engine: type,
    comptime backend: config.Backend,
    comptime Spec: type,
    allocator: std.mem.Allocator,
    args: config.Args,
    workload: config.Workload,
    request: Spec.Request,
) ![]u8 {
    if (args.product_identity) |identity| try identity.validate();
    const resource_before = try process_usage.sample();
    const blake2_selection = blake2_hash.getDefaultBackendSelection();
    const requested_blake2_mode: blake2_hash.BackendMode = switch (args.blake2_backend) {
        .auto => .auto,
        .scalar => .scalar,
        .simd => .simd,
    };
    if (blake2_selection.requested != requested_blake2_mode)
        return error.Blake2BackendAdmissionMismatch;
    const protocol_parameters = args.protocol.parameters();
    var fri_config = try stwo.core.fri.FriConfig.init(
        protocol_parameters.log_last_layer_degree_bound,
        protocol_parameters.log_blowup_factor,
        protocol_parameters.n_queries,
    );
    fri_config.fold_step = protocol_parameters.fold_step;
    const pcs_config = stwo.core.pcs.PcsConfig{
        .pow_bits = protocol_parameters.pow_bits,
        .fri_config = fri_config,
    };
    const workload_geometry = try examples.geometry(workload);
    const workload_admission = try config.admitWorkload(workload, args.resource_profile);
    if (workload_admission.geometry.log_rows != workload_geometry.trace_log_rows or
        workload_admission.geometry.rows != workload_geometry.trace_rows or
        workload_admission.geometry.committed_columns != workload_geometry.committed_columns or
        workload_admission.geometry.committed_cells != workload_geometry.committed_trace_cells)
        return error.ResourceAdmissionGeometryMismatch;
    const max_circle_log = try Spec.requiredCircleLog(request, pcs_config);

    var init_timer = try std.time.Timer.start();
    if (comptime backend == .metal_hybrid) {
        const policy: Engine.RuntimeInitializationPolicy = switch (args.metal_runtime.mode) {
            .source_jit => .source_jit,
            .authenticated_aot => .{ .authenticated_aot = .{
                .bundle_path = args.metal_runtime.aot_bundle.?,
                .manifest_sha256 = args.metal_runtime.manifest_sha256.?,
            } },
        };
        try Engine.initializeRuntime(allocator, policy);
    }
    if (comptime @hasDecl(Engine, "warmup")) try Engine.warmup();
    var session = try Engine.initSession(
        allocator,
        pcs_config,
        max_circle_log,
        HOST_TWIDDLE_BUDGET_BYTES,
    );
    defer session.deinit(allocator);
    const session_construction = session.constructionTelemetry();
    const backend_init_seconds = nsToSeconds(init_timer.read());

    const warmup_seconds = try allocator.alloc(f64, args.warmups);
    defer allocator.free(warmup_seconds);
    const warmup_telemetry = try allocator.alloc(
        report_mod.BackendTelemetryDelta,
        if (backend == .metal_hybrid) args.warmups else 0,
    );
    defer allocator.free(warmup_telemetry);
    var observed_statement: ?Spec.Statement = null;
    for (warmup_seconds, 0..) |*elapsed, index| {
        var outcome = try runGatedSample(
            Engine,
            backend,
            Spec,
            &session,
            allocator,
            pcs_config,
            request,
            workload_geometry,
            false,
        );
        defer outcome.sample.deinit(allocator);
        if (observed_statement) |expected| {
            if (!std.meta.eql(expected, outcome.sample.statement))
                return error.ProverStatementMismatch;
        } else {
            observed_statement = outcome.sample.statement;
        }
        elapsed.* = outcome.sample.timing.request_seconds;
        if (comptime backend == .metal_hybrid) warmup_telemetry[index] = outcome.telemetry.?;
    }
    const post_warmup_telemetry: ?telemetry.WarmupSnapshot = if (backend == .metal_hybrid) blk: {
        const snapshot = try Engine.telemetrySnapshot();
        break :blk telemetry.postWarmup(snapshot);
    } else null;

    const samples = try allocator.alloc(report_mod.Sample, args.samples);
    defer allocator.free(samples);
    const input_values = try allocator.alloc(f64, args.samples);
    defer allocator.free(input_values);
    const prove_values = try allocator.alloc(f64, args.samples);
    defer allocator.free(prove_values);
    const encode_values = try allocator.alloc(f64, args.samples);
    defer allocator.free(encode_values);
    const verify_values = try allocator.alloc(f64, args.samples);
    defer allocator.free(verify_values);
    const request_values = try allocator.alloc(f64, args.samples);
    defer allocator.free(request_values);
    const native_rates = try allocator.alloc(f64, args.samples);
    defer allocator.free(native_rates);
    const request_native_rates = try allocator.alloc(f64, args.samples);
    defer allocator.free(request_native_rates);
    const trace_row_rates = try allocator.alloc(f64, args.samples);
    defer allocator.free(trace_row_rates);
    const request_trace_row_rates = try allocator.alloc(f64, args.samples);
    defer allocator.free(request_trace_row_rates);
    const cell_rates = try allocator.alloc(f64, args.samples);
    defer allocator.free(cell_rates);
    const proof_records = try allocator.alloc(report_mod.CanonicalProof, args.samples);
    defer allocator.free(proof_records);
    const proof_digest_hexes = try allocator.alloc([64]u8, args.samples);
    defer allocator.free(proof_digest_hexes);
    const sample_telemetry = try allocator.alloc(
        report_mod.BackendTelemetryDelta,
        if (backend == .metal_hybrid) args.samples else 0,
    );
    defer allocator.free(sample_telemetry);
    const sample_stage_profiles = try allocator.alloc(
        report_mod.StageProfile,
        if (args.profiled) args.samples else 0,
    );
    var initialized_stage_profiles: usize = 0;
    defer {
        for (sample_stage_profiles[0..initialized_stage_profiles]) |*profile| profile.deinit(allocator);
        allocator.free(sample_stage_profiles);
    }

    var canonical_proof: ?[]u8 = null;
    defer if (canonical_proof) |bytes| allocator.free(bytes);
    var canonical_statement: ?Spec.Statement = null;
    var all_samples_byte_identical = true;
    for (samples, 0..) |*sample, index| {
        const gated = try runGatedSample(
            Engine,
            backend,
            Spec,
            &session,
            allocator,
            pcs_config,
            request,
            workload_geometry,
            args.profiled,
        );
        var outcome = gated.sample;
        var outcome_owned = true;
        defer {
            if (outcome_owned) allocator.free(outcome.canonical_proof);
            if (outcome.stage_profile) |*profile| profile.deinit(allocator);
        }
        if (comptime backend == .metal_hybrid) sample_telemetry[index] = gated.telemetry.?;
        if (args.profiled) {
            sample_stage_profiles[index] = outcome.stage_profile.?;
            outcome.stage_profile = null;
            initialized_stage_profiles += 1;
        }
        if (observed_statement) |expected| {
            if (!std.meta.eql(expected, outcome.statement))
                return error.ProverStatementMismatch;
        } else {
            observed_statement = outcome.statement;
        }

        var proof_digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(outcome.canonical_proof, &proof_digest, .{});
        proof_digest_hexes[index] = std.fmt.bytesToHex(proof_digest, .lower);
        proof_records[index] = .{
            .bytes = outcome.canonical_proof.len,
            .sha256 = &proof_digest_hexes[index],
        };
        if (canonical_proof) |expected| {
            all_samples_byte_identical = all_samples_byte_identical and
                std.mem.eql(u8, expected, outcome.canonical_proof);
        } else {
            canonical_proof = outcome.canonical_proof;
            canonical_statement = outcome.statement;
            outcome_owned = false;
        }
        sample.* = outcome.timing;
        input_values[index] = sample.input_seconds;
        prove_values[index] = sample.prove_seconds;
        encode_values[index] = sample.proof_encode_seconds;
        verify_values[index] = sample.verify_seconds;
        request_values[index] = sample.request_seconds;
        native_rates[index] = sample.native_mhz;
        request_native_rates[index] = sample.request_native_mhz;
        trace_row_rates[index] = sample.trace_row_mhz;
        request_trace_row_rates[index] = sample.request_trace_row_mhz;
        cell_rates[index] = sample.committed_mcells_per_second;
    }

    const proof_artifact_binding: ?report_mod.ProofArtifactBinding = if (args.proof_artifact_out) |path| blk: {
        try Spec.writeArtifact(
            allocator,
            path,
            pcs_config,
            canonical_statement.?,
            canonical_proof.?,
        );
        break :blk .{
            .path = args.proof_artifact_report_path orelse path,
            .sample_index = 0,
            .bytes = proof_records[0].bytes,
            .sha256 = proof_records[0].sha256,
            .artifact_schema_version = examples_artifact.SCHEMA_VERSION,
            .upstream_commit = examples_artifact.UPSTREAM_COMMIT,
            .exchange_mode = examples_artifact.EXCHANGE_MODE,
        };
    } else null;

    const workload_digest = examples.descriptorDigest(workload, args.protocol);
    var workload_digest_hex = std.fmt.bytesToHex(workload_digest, .lower);

    var provenance_owned = if (args.product_identity) |identity|
        try provenance.collectEmbedded(allocator, identity.implementation_commit)
    else
        try provenance.collect(allocator);
    defer provenance_owned.deinit(allocator);
    const git_status = if (args.product_identity != null)
        provenance.GitStatus{
            .output = try allocator.alloc(u8, 0),
            .available = true,
        }
    else
        try provenance.collectGitStatus(allocator);
    defer allocator.free(git_status.output);
    const overrides = provenance_owned.environment_overrides;

    const input_summary = try statistics.summarize(allocator, input_values);
    const prove_summary = try statistics.summarize(allocator, prove_values);
    const encode_summary = try statistics.summarize(allocator, encode_values);
    const verify_summary = try statistics.summarize(allocator, verify_values);
    const request_summary = try statistics.summarize(allocator, request_values);
    const native_summary = try statistics.summarize(allocator, native_rates);
    const request_native_summary = try statistics.summarize(allocator, request_native_rates);
    const trace_row_summary = try statistics.summarize(allocator, trace_row_rates);
    const request_trace_row_summary = try statistics.summarize(allocator, request_trace_row_rates);
    const cell_summary = try statistics.summarize(allocator, cell_rates);
    const minimum_samples: usize = if (prove_summary.median < 1.0) 5 else 3;
    const meets_sampling_contract = args.warmups >= config.MIN_HEADLINE_WARMUPS and
        args.samples >= minimum_samples;
    const evidence_class = args.evidenceClass(meets_sampling_contract);
    const git_dirty = if (args.product_identity) |identity|
        identity.implementation_dirty
    else
        git_status.output.len != 0;
    const provenance_complete = provenance_owned.git_available and git_status.available and
        overrides.len == 0;
    const telemetry_valid = telemetry.valid(backend, warmup_telemetry, sample_telemetry);
    const byte_identical_verified_samples =
        args.samples == proof_records.len and all_samples_byte_identical;
    const headline_requirements = report_mod.HeadlineRequirements{
        .verified_unprofiled = evidence_class == .verified_unprofiled,
        .sampling_contract = meets_sampling_contract,
        .functional_protocol = args.protocol != .smoke,
        .release_fast = builtin.mode == .ReleaseFast,
        .clean_complete_provenance = provenance_complete and !git_dirty,
        .thread_parallelism_enabled = !builtin.single_threaded,
        .byte_identical_verified_samples = byte_identical_verified_samples,
        .backend_telemetry_valid = telemetry_valid,
    };
    const headline_eligible = headlineRequirementsMet(headline_requirements);
    const telemetry_totals = telemetry.sum(warmup_telemetry, sample_telemetry);
    var runtime_source_hex: [64]u8 = undefined;
    var runtime_manifest_hex: [64]u8 = undefined;
    var runtime_metallib_hex: [64]u8 = undefined;
    const runtime_platform_identity: ?[]u8 = if (comptime backend == .metal_hybrid)
        (try Engine.runtimePlatformIdentityAlloc(allocator)) orelse
            return error.MetalRuntimeIdentityMissing
    else
        null;
    defer if (runtime_platform_identity) |value| allocator.free(value);
    const runtime_admission: ?report_mod.RuntimeAdmission = if (comptime backend == .metal_hybrid) blk: {
        const lifecycle = Engine.runtimeLifecycleSnapshot();
        const identity = lifecycle.identity orelse return error.MetalRuntimeIdentityMissing;
        runtime_source_hex = std.fmt.bytesToHex(identity.source_sha256, .lower);
        if (identity.manifest_sha256) |digest|
            runtime_manifest_hex = std.fmt.bytesToHex(digest, .lower);
        if (identity.metallib_sha256) |digest|
            runtime_metallib_hex = std.fmt.bytesToHex(digest, .lower);
        break :blk .{
            .initialized = lifecycle.initialized,
            .origin = @tagName(identity.origin),
            .source_sha256 = &runtime_source_hex,
            .manifest_sha256 = if (identity.manifest_sha256 != null) &runtime_manifest_hex else null,
            .metallib_sha256 = if (identity.metallib_sha256 != null) &runtime_metallib_hex else null,
            .metallib_bytes = identity.metallib_bytes,
            .active_call_leases = lifecycle.active_call_leases,
            .live_resident_resources = lifecycle.live_resident_resources,
            .initialization_count = lifecycle.initialization_count,
            .shutdown_count = lifecycle.shutdown_count,
            .platform_identity = runtime_platform_identity.?,
        };
    } else null;

    const resource_after = try process_usage.sample();
    const resource_delta = try process_usage.difference(resource_before, resource_after);
    const report = report_mod.Report{
        .product_identity = args.product_identity,
        .backend = backend,
        .evidence_class = evidence_class,
        .profiled = args.profiled,
        .provenance = .{
            .git_commit = provenance_owned.git_commit,
            .git_dirty = git_dirty,
            .zig_version = builtin.zig_version_string,
            .optimization = @tagName(builtin.mode),
            .target_os = @tagName(builtin.os.tag),
            .target_arch = @tagName(builtin.cpu.arch),
            .cpu_count = try std.Thread.getCpuCount(),
            .simd_pack_width = M31_PACK_WIDTH,
            .blake2s_requested_backend = @tagName(blake2_selection.requested),
            .blake2s_effective_backend = @tagName(blake2_selection.effective),
            .blake2s_simd_supported = blake2_selection.simd_supported,
            .single_threaded = builtin.single_threaded,
            .thread_parallelism_enabled = !builtin.single_threaded,
            .environment_overrides = overrides,
            .complete = provenance_complete,
        },
        .protocol = .{
            .name = args.protocol,
            .pow_bits = protocol_parameters.pow_bits,
            .log_blowup_factor = protocol_parameters.log_blowup_factor,
            .log_last_layer_degree_bound = protocol_parameters.log_last_layer_degree_bound,
            .n_queries = protocol_parameters.n_queries,
            .fold_step = protocol_parameters.fold_step,
        },
        .workload = .{
            .name = examples.name(workload),
            .descriptor_sha256 = &workload_digest_hex,
            .parameters = examples.parameters(workload),
            .trace_log_rows = workload_geometry.trace_log_rows,
            .trace_rows = workload_geometry.trace_rows,
            .committed_trees = workload_geometry.committed_trees,
            .committed_columns = workload_geometry.committed_columns,
            .committed_trace_cells = workload_geometry.committed_trace_cells,
            .native_unit = workload_geometry.native_unit,
            .native_units = workload_geometry.native_units,
        },
        .resource_admission = .{
            .profile = workload_admission.profile,
            .accounted_bytes_per_committed_cell = workload_admission.accounted_bytes_per_committed_cell,
            .committed_cells = workload_admission.geometry.committed_cells,
            .accounted_bytes = workload_admission.geometry.accounted_bytes,
            .max_committed_cells = workload_admission.limits.max_committed_cells,
            .max_accounted_bytes = workload_admission.limits.max_accounted_bytes,
        },
        .resources = .{
            .source = resource_delta.source,
            .measured_warmups = args.warmups,
            .measured_samples = args.samples,
            .lifetime_peak_physical_footprint_bytes = resource_delta.lifetime_peak_physical_footprint_bytes,
            .energy_nj = resource_delta.energy_nj,
            .instructions = resource_delta.instructions,
            .cycles = resource_delta.cycles,
            .canonical_proof_bytes = proof_records[0].bytes,
            .complete = resource_delta.available(),
            .unavailable_reason = resource_delta.unavailable_reason,
        },
        .proof = .{
            .samples = proof_records,
            .verified_samples = args.samples,
            .all_samples_byte_identical = all_samples_byte_identical,
            .artifact = proof_artifact_binding,
        },
        .session = .{
            .max_circle_log = max_circle_log,
            .host_byte_budget = HOST_TWIDDLE_BUDGET_BYTES,
            .retained_host_twiddle_bytes = session_construction.retained_twiddle_bytes,
            .tower_build_count = session_construction.tower_build_count,
        },
        .runtime_admission = runtime_admission,
        .backend_telemetry = if (backend == .metal_hybrid) .{
            .post_warmup_pipeline_cache = post_warmup_telemetry.?.pipeline_cache,
            .post_warmup_archive_store = post_warmup_telemetry.?.archive_store,
            .warmups = warmup_telemetry,
            .samples = sample_telemetry,
            .total_metal_dispatches = telemetry_totals.metal_dispatches,
            .total_cpu_fallbacks = telemetry_totals.cpu_fallbacks,
            .valid = telemetry_valid,
        } else null,
        .timing = .{
            .backend_init_seconds = backend_init_seconds,
            .warmup_request_seconds = warmup_seconds,
            .samples = samples,
            .stage_profiles = if (args.profiled) sample_stage_profiles else null,
            .input_seconds = input_summary,
            .prove_seconds = prove_summary,
            .proof_encode_seconds = encode_summary,
            .verify_seconds = verify_summary,
            .request_seconds = request_summary,
        },
        .throughput = .{
            .headline_eligible = headline_eligible,
            .headline_native_mhz = if (headline_eligible) native_summary else null,
            .diagnostic_native_mhz = if (evidence_class == .profiled_diagnostic) native_summary else null,
            .headline_request_native_mhz = if (headline_eligible) request_native_summary else null,
            .diagnostic_request_native_mhz = if (evidence_class == .profiled_diagnostic) request_native_summary else null,
            .headline_trace_row_mhz = if (headline_eligible) trace_row_summary else null,
            .diagnostic_trace_row_mhz = if (evidence_class == .profiled_diagnostic) trace_row_summary else null,
            .headline_request_trace_row_mhz = if (headline_eligible) request_trace_row_summary else null,
            .diagnostic_request_trace_row_mhz = if (evidence_class == .profiled_diagnostic) request_trace_row_summary else null,
            .headline_committed_mcells_per_second = if (headline_eligible) cell_summary else null,
            .diagnostic_committed_mcells_per_second = if (evidence_class == .profiled_diagnostic) cell_summary else null,
            .headline_requirements = headline_requirements,
        },
    };
    return report_mod.encodeAlloc(allocator, report);
}

fn runGatedSample(
    comptime Engine: type,
    comptime backend: config.Backend,
    comptime Spec: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: stwo.core.pcs.PcsConfig,
    request: Spec.Request,
    workload_geometry: examples.Geometry,
    profiled: bool,
) !GatedSampleOutcome(Spec.Statement) {
    if (comptime backend == .metal_hybrid) {
        const before = try Engine.telemetrySnapshot();
        var sample = try runSample(
            Engine,
            Spec,
            session,
            allocator,
            pcs_config,
            request,
            workload_geometry,
            profiled,
        );
        errdefer sample.deinit(allocator);
        const after = try Engine.telemetrySnapshot();
        const delta = after.delta(before);
        try delta.requireMetalDispatch();
        return .{ .sample = sample, .telemetry = telemetry.request(delta) };
    }
    return .{
        .sample = try runSample(
            Engine,
            Spec,
            session,
            allocator,
            pcs_config,
            request,
            workload_geometry,
            profiled,
        ),
        .telemetry = null,
    };
}

fn runSample(
    comptime Engine: type,
    comptime Spec: type,
    session: *const Engine.Session,
    allocator: std.mem.Allocator,
    pcs_config: stwo.core.pcs.PcsConfig,
    request: Spec.Request,
    workload_geometry: examples.Geometry,
    profiled: bool,
) !SampleOutcome(Spec.Statement) {
    var recorder = stage_profile.Recorder.init(allocator, @tagName(builtin.mode), Spec.example_name);
    defer recorder.deinit();

    var request_timer = try std.time.Timer.start();
    var input_timer = try std.time.Timer.start();
    const prepared = if (comptime @hasDecl(Spec, "prepareInputWithEngine"))
        try Spec.prepareInputWithEngine(Engine, allocator, request)
    else
        try Spec.prepareInput(allocator, request);
    const input_seconds = nsToSeconds(input_timer.read());
    var prepared_owned = true;
    errdefer if (prepared_owned) {
        var owned = prepared;
        owned.deinit(allocator);
    };
    var prove_timer = try std.time.Timer.start();
    prepared_owned = false;
    const output = try Spec.provePrepared(
        Engine,
        session,
        allocator,
        pcs_config,
        prepared,
        if (profiled) &recorder else null,
    );
    const prove_seconds = nsToSeconds(prove_timer.read());
    var proof_owned = true;
    defer if (proof_owned) {
        var proof = output.proof;
        proof.deinit(allocator);
    };
    try Spec.validateOutputStatement(request, output.statement);

    var encode_timer = try std.time.Timer.start();
    const canonical = try proof_wire.encodeProofBytes(allocator, output.proof);
    errdefer allocator.free(canonical);
    const encode_seconds = nsToSeconds(encode_timer.read());

    var verify_timer = try std.time.Timer.start();
    proof_owned = false;
    try Spec.verify(allocator, pcs_config, output.statement, output.proof);
    const verify_seconds = nsToSeconds(verify_timer.read());
    const request_seconds = nsToSeconds(request_timer.read());
    return .{
        .timing = .{
            .input_seconds = input_seconds,
            .prove_seconds = prove_seconds,
            .proof_encode_seconds = encode_seconds,
            .verify_seconds = verify_seconds,
            .request_seconds = request_seconds,
            .native_mhz = rate(workload_geometry.native_units, prove_seconds),
            .request_native_mhz = rate(workload_geometry.native_units, request_seconds),
            .trace_row_mhz = rate(workload_geometry.trace_rows, prove_seconds),
            .request_trace_row_mhz = rate(workload_geometry.trace_rows, request_seconds),
            .committed_mcells_per_second = rate(workload_geometry.committed_trace_cells, prove_seconds),
        },
        .statement = output.statement,
        .canonical_proof = canonical,
        .stage_profile = if (profiled) try recorder.snapshot(allocator) else null,
    };
}

fn headlineRequirementsMet(requirements: report_mod.HeadlineRequirements) bool {
    inline for (std.meta.fields(report_mod.HeadlineRequirements)) |field| {
        if (!@field(requirements, field.name)) return false;
    }
    return true;
}

fn nsToSeconds(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / std.time.ns_per_s;
}

fn rate(units: u64, seconds: f64) f64 {
    return @as(f64, @floatFromInt(units)) / seconds / 1_000_000.0;
}

test {
    _ = config;
    _ = report_mod;
    _ = statistics;
}

test "native proof runner: headline requirements fail closed" {
    var requirements = report_mod.HeadlineRequirements{
        .verified_unprofiled = true,
        .sampling_contract = true,
        .functional_protocol = true,
        .release_fast = true,
        .clean_complete_provenance = true,
        .thread_parallelism_enabled = true,
        .byte_identical_verified_samples = true,
        .backend_telemetry_valid = true,
    };
    try std.testing.expect(headlineRequirementsMet(requirements));
    requirements.clean_complete_provenance = false;
    try std.testing.expect(!headlineRequirementsMet(requirements));
}

test "native proof runner: oracle artifact wraps exact canonical bytes" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "proof.json" });
    defer std.testing.allocator.free(path);

    const pcs_config = stwo.core.pcs.PcsConfig{
        .pow_bits = 10,
        .fri_config = try stwo.core.fri.FriConfig.init(0, 1, 3),
    };
    const statement = stwo.examples.wide_fibonacci.Statement{ .log_n_rows = 12, .sequence_len = 16 };
    const canonical = [_]u8{ 0, 1, 2, 127, 128, 255 };
    try examples.WideFibonacciSpec.writeArtifact(
        std.testing.allocator,
        path,
        pcs_config,
        statement,
        &canonical,
    );

    var parsed = try examples_artifact.readArtifact(std.testing.allocator, path);
    defer parsed.deinit();
    const artifact = parsed.value;
    try std.testing.expectEqualStrings(examples_artifact.UPSTREAM_COMMIT, artifact.upstream_commit);
    try std.testing.expectEqualStrings("zig", artifact.generator);
    try std.testing.expectEqualStrings("wide_fibonacci", artifact.example);
    try std.testing.expectEqual(@as(u32, 10), artifact.pcs_config.pow_bits);
    try std.testing.expectEqual(@as(u32, 12), artifact.wide_fibonacci_statement.?.log_n_rows);
    try std.testing.expectEqual(@as(u32, 16), artifact.wide_fibonacci_statement.?.sequence_len);
    const decoded = try examples_artifact.hexToBytesAlloc(std.testing.allocator, artifact.proof_bytes_hex);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &canonical, decoded);
}
