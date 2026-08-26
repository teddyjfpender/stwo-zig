//! Ordinary `prove`/`bench --profiled` transaction for the exact Poseidon2
//! execution profile.
//!
//! Routing is selected only from authenticated ELF admission metadata. The
//! base adapter never enters this module, and this module never falls back to
//! base RV32IM execution or the ordinary proof envelope.

const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const capabilities = @import("riscv_cpu_capabilities");
const artifact_validation = @import("artifact_validation.zig");
const benchmark_report = @import("benchmark_report.zig");
const identity = @import("guest_profile_identity.zig");
const pcs_profile = @import("pcs_profile.zig");
const resource_usage = @import("../resource_usage.zig");
const transcript_state = @import("transcript_state.zig");
const verified_request_attempt = @import("verified_request_attempt.zig");

const BenchmarkReport = benchmark_report.BenchmarkReport;
const ProveReport = benchmark_report.ProveReport;
const ResidentPolynomialTelemetry = benchmark_report.ResidentPolynomialTelemetry;
const seconds = benchmark_report.seconds;
const witnessSeconds = benchmark_report.witnessSeconds;

/// Canonical one-shot AIR capacity. Workloads above this exact geometry must
/// use segmented execution and recursion; the guest adapter never admits a
/// larger runner trace that the statement layer would later reject.
pub const maximum_profile_steps: usize =
    stwo.frontends.riscv.prover_mod.MAX_EXECUTION_STEPS;

const artifact_limits: stwo.frontends.riscv.prover_mod.guest_precompile.proof_artifact.Limits = .{
    .max_artifact_bytes = 256 * 1024 * 1024,
    .max_proof_bytes = 128 * 1024 * 1024,
    .max_input_bytes = 16 * 1024 * 1024,
    .max_output_bytes = 16 * 1024 * 1024,
    .max_queries = 1024,
    .max_pow_bits = 128,
};

fn readProofPhaseClock(context: *anyopaque) anyerror!u64 {
    const timer: *std.time.Timer = @ptrCast(@alignCast(context));
    return timer.read();
}

pub fn run(
    comptime Engine: type,
    comptime backend: anytype,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: anytype,
    process_identity: artifact_validation.ProcessIdentity,
) ![]u8 {
    comptime identity.assertProductCapability(capabilities, @tagName(backend));
    return switch (options.mode) {
        .prove => runProve(
            Engine,
            backend,
            allocator,
            elf_path,
            input_path,
            options,
            process_identity,
            null,
        ),
        .bench => |benchmark| runBenchmark(
            Engine,
            backend,
            allocator,
            elf_path,
            input_path,
            options,
            benchmark,
            process_identity,
        ),
    };
}

fn runProve(
    comptime Engine: type,
    comptime backend: anytype,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: anytype,
    process_identity: artifact_validation.ProcessIdentity,
    profiled_sample_index: ?usize,
) ![]u8 {
    const proof_temporary = options.proof_temporary orelse
        return error.AdapterNotReleaseGated;
    if (options.protocol == .smoke) return error.UnsupportedGuestProtocol;
    var total_timer = try std.time.Timer.start();

    const runner = stwo.frontends.riscv.runner;
    const prover = stwo.frontends.riscv.prover_mod;
    const ProfileEngine = profileEngine(backend);

    const elf = try readFileBounded(allocator, elf_path, 64 * 1024 * 1024);
    defer allocator.free(elf);
    try runner.elf_loader.validateReleaseAbiForProfile(
        elf,
        .rv32im_zkvm_poseidon2_v1,
    );
    var elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf, &elf_digest, .{});

    const input = if (input_path) |path|
        try readFileBounded(allocator, path, artifact_limits.max_input_bytes)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(input);
    var input_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &input_digest, .{});

    const config = pcs_profile.select(options.protocol);
    var recorder = stwo.prover.stage_profile.Recorder.initWithOptions(
        allocator,
        @tagName(@import("builtin").mode),
        identity.TASK_PROFILE_EXAMPLE,
        .{
            .capture_tasks = profiled_sample_index != null,
            .capture_work = profiled_sample_index != null,
        },
    );
    defer recorder.deinit();

    const telemetry_before = if (comptime backend == .metal)
        try ProfileEngine.telemetrySnapshot()
    else {};
    const lifecycle_before = if (comptime backend == .metal) lifecycle: {
        const current = ProfileEngine.runtimeLifecycleSnapshot();
        try guestIntegration(backend).validateRuntimeLifecycle(current);
        break :lifecycle current;
    } else {};

    var execution_timer = try std.time.Timer.start();
    var profile_phase_timer: ?std.time.Timer = if (profiled_sample_index != null)
        try std.time.Timer.start()
    else
        null;
    var execution = try runner.runPoseidon2ExtensionWithInput(
        allocator,
        elf,
        input,
        maximum_profile_steps,
    );
    defer execution.deinit();
    try prover.admitRunForProving(&execution.base);
    if (execution.calls.len() == 0) return error.GuestProfileCallRequired;
    if (execution.calls.len() != execution.execution_rows.rows().len)
        return error.GuestProfileExecutionAuthorityMismatch;
    const execution_ns = execution_timer.read();
    const guest_execution_ns: ?u64 = if (profile_phase_timer) |*timer|
        timer.read()
    else
        null;

    var phase_meter = prover.proof_phase_meter.Meter.init(
        if (profile_phase_timer) |*timer|
            .{ .context = timer, .now_fn = readProofPhaseClock }
        else
            null,
    );
    var public = try OwnedPublicData.init(allocator, &execution.base);
    defer public.deinit(allocator);
    var proving_timer = try std.time.Timer.start();
    var prove_channel = ProfileEngine.Channel{};
    var output = if (profiled_sample_index != null)
        try prover.provePoseidon2WithEngineAndPublicDataUsingChannelAndPhaseMeter(
            ProfileEngine,
            allocator,
            config,
            &execution.base.execution_trace,
            &execution.calls,
            &execution.execution_rows,
            &execution.base.state_chain_tracker,
            &execution.base.rw_memory,
            &recorder,
            public.value,
            &prove_channel,
            &phase_meter,
        )
    else
        try prover.provePoseidon2WithEngineAndPublicDataUsingChannel(
            ProfileEngine,
            allocator,
            config,
            &execution.base.execution_trace,
            &execution.calls,
            &execution.execution_rows,
            &execution.base.state_chain_tracker,
            &execution.base.rw_memory,
            &recorder,
            public.value,
            &prove_channel,
        );
    var proof_moved = false;
    defer if (proof_moved)
        output.deinitAfterProofMoved(allocator)
    else
        output.deinit(allocator);

    var resident_polynomial_telemetry: ResidentPolynomialTelemetry = .{};
    if (comptime backend == .metal) {
        const lifecycle_after = ProfileEngine.runtimeLifecycleSnapshot();
        try guestIntegration(backend).validateRuntimeLifecycle(lifecycle_after);
        if (!std.meta.eql(lifecycle_before.identity, lifecycle_after.identity))
            return error.RuntimeIdentityChangedDuringProof;
        const telemetry_after = try ProfileEngine.telemetrySnapshot();
        const delta = telemetry_after.delta(telemetry_before);
        try guestIntegration(backend).validateTransactionDelta(delta);
        resident_polynomial_telemetry = ResidentPolynomialTelemetry.fromDelta(delta);
        resident_polynomial_telemetry.verified_samples_with_dispatch = 1;
    }

    const prove_transcript_digest = transcript_state.receiptDigest(
        prove_channel.digestBytes(),
        prove_channel.n_draws,
    );
    const proving_with_witness_seconds = seconds(proving_timer.read());
    const proving_including_witness_ns: ?u64 = if (profile_phase_timer) |*timer|
        std.math.sub(u64, timer.read(), guest_execution_ns.?) catch
            return error.ProfileClockRegression
    else
        null;
    const witness_ns: ?u64 = if (profiled_sample_index != null)
        phase_meter.witness_ns
    else
        null;
    const proving_ns: ?u64 = if (witness_ns) |witness|
        std.math.sub(u64, proving_including_witness_ns.?, witness) catch
            return error.ProfileWitnessExceedsProofBoundary
    else
        null;

    const artifact_wire = prover.guest_precompile.proof_artifact;
    const encoded = try artifact_wire.encodeAllocWithLimits(allocator, .{
        .pcs_config = config,
        .statement = &output.statement,
        .extension = &output.extension,
        .artifact = output.artifact,
        .interaction_claim = output.interaction_claim,
        .proof = &output.proof,
    }, artifact_limits);
    defer allocator.free(encoded);

    var verification_timer = try std.time.Timer.start();
    proof_moved = true;
    var verify_channel = Engine.Channel{};
    try prover.verifyPoseidon2WithEngineUsingChannel(
        Engine,
        allocator,
        config,
        output.statement,
        output.extension,
        output.artifact,
        output.proof,
        output.interaction_claim,
        &verify_channel,
    );
    const verify_transcript_digest = transcript_state.receiptDigest(
        verify_channel.digestBytes(),
        verify_channel.n_draws,
    );
    if (!std.mem.eql(u8, &prove_transcript_digest, &verify_transcript_digest))
        return error.TranscriptStateDigestMismatch;
    const verification_ns = verification_timer.read();

    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    try benchmark_report.requireNativeOnlyStages(profile.stages);
    const witness_seconds = if (witness_ns) |value|
        seconds(value)
    else
        witnessSeconds(profile.stages);
    const proving_seconds = if (proving_ns) |value|
        seconds(value)
    else
        @max(0.0, proving_with_witness_seconds - witness_seconds);

    var profiled_attempt: ?verified_request_attempt.Attempt = if (profiled_sample_index) |index|
        try verified_request_attempt.Attempt.capture(
            allocator,
            index,
            guest_execution_ns.?,
            witness_ns.?,
            proving_ns.?,
            verification_ns,
            &recorder,
        )
    else
        null;
    defer if (profiled_attempt) |*attempt| attempt.deinit(allocator);
    const encoded_attempt: ?[]u8 = if (profiled_attempt) |attempt|
        try std.json.Stringify.valueAlloc(allocator, attempt, .{
            .emit_null_optional_fields = false,
        })
    else
        null;
    defer if (encoded_attempt) |attempt| allocator.free(attempt);

    const statement_digest = identity.statementDigest(
        @tagName(options.protocol),
        config,
        elf_digest,
        input_digest,
        output.artifact.statement_digest,
    );
    const statement_hex = std.fmt.bytesToHex(statement_digest, .lower);
    const transcript_hex = std.fmt.bytesToHex(prove_transcript_digest, .lower);
    const executable_hex = std.fmt.bytesToHex(
        process_identity.executable_sha256,
        .lower,
    );
    try stwo.interop.atomic_file.writeExclusive(allocator, proof_temporary, encoded);

    const telemetry_json: []const u8 = if (comptime backend == .metal)
        try std.fmt.allocPrint(
            allocator,
            "\"resident_polynomial_telemetry\":{{" ++
                "\"eligible_base_components\":{d}," ++
                "\"eligible_lookup_components\":{d}," ++
                "\"base_batch_dispatches\":{d}," ++
                "\"lookup_batch_dispatches\":{d}," ++
                "\"declines\":{d}," ++
                "\"verified_samples_with_dispatch\":{d}}},",
            .{
                resident_polynomial_telemetry.eligible_base_components,
                resident_polynomial_telemetry.eligible_lookup_components,
                resident_polynomial_telemetry.base_batch_dispatches,
                resident_polynomial_telemetry.lookup_batch_dispatches,
                resident_polynomial_telemetry.declines,
                resident_polynomial_telemetry.verified_samples_with_dispatch,
            },
        )
    else
        "";
    defer if (comptime backend == .metal) allocator.free(telemetry_json);
    const attempt_json: []const u8 = if (encoded_attempt) |attempt|
        try std.fmt.allocPrint(allocator, "\"profiled_attempt\":{s},", .{attempt})
    else
        "";
    defer if (encoded_attempt != null) allocator.free(attempt_json);
    const total_components = std.math.add(
        u32,
        output.statement.n_components,
        @intCast(output.extension.components.len),
    ) catch return error.InvalidComponentCount;

    return std.fmt.allocPrint(
        allocator,
        "{{\"schema\":\"{s}\",\"release_status\":\"{s}\"," ++
            "\"experimental\":{},\"verified_in_process\":true," ++
            "\"total_steps\":{d},\"n_components\":{d}," ++
            "\"execution_seconds\":{d},\"witness_seconds\":{d}," ++
            "\"proving_seconds\":{d},\"verification_seconds\":{d}," ++
            "\"total_seconds\":{d},{s}{s}" ++
            "\"statement_sha256\":\"{s}\"," ++
            "\"transcript_state_blake2s\":\"{s}\"," ++
            "\"implementation_commit\":\"{s}\",\"implementation_dirty\":{}," ++
            "\"executable_sha256\":\"{s}\",\"proof_path\":\"{s}\"}}",
        .{
            benchmark_report.proveSchema(profiled_sample_index != null),
            stwo.interop.riscv_artifact.RELEASE_STATUS,
            options.experimental,
            output.statement.total_steps,
            total_components,
            seconds(execution_ns),
            witness_seconds,
            proving_seconds,
            seconds(verification_ns),
            seconds(total_timer.read()),
            telemetry_json,
            attempt_json,
            &statement_hex,
            &transcript_hex,
            build_identity.implementation_commit,
            build_identity.implementation_dirty,
            &executable_hex,
            options.proof_report_path orelse proof_temporary,
        },
    );
}

fn runBenchmark(
    comptime Engine: type,
    comptime backend: anytype,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: anytype,
    benchmark: anytype,
    process_identity: artifact_validation.ProcessIdentity,
) ![]u8 {
    const sample_seconds = try allocator.alloc(f64, benchmark.samples);
    defer allocator.free(sample_seconds);
    const retained = try allocator.alloc(
        std.json.Parsed(ProveReport),
        if (benchmark.profiled) benchmark.samples else 0,
    );
    var retained_count: usize = 0;
    defer {
        for (retained[0..retained_count]) |*report| report.deinit();
        allocator.free(retained);
    }
    const run_nonce = std.time.nanoTimestamp();
    var artifact_digest: ?[32]u8 = null;
    var statement_digest: [32]u8 = undefined;
    var transcript_digest: ?[32]u8 = null;
    var total_steps: u32 = 0;
    var n_components: u32 = 0;
    var execution_seconds: f64 = 0;
    var witness_seconds: f64 = 0;
    var proving_seconds: f64 = 0;
    var verification_seconds: f64 = 0;
    var telemetry: ResidentPolynomialTelemetry = .{};

    const resources_before = resource_usage.capture();
    const iterations = try std.math.add(usize, benchmark.warmups, benchmark.samples);
    for (0..iterations) |iteration| {
        const is_sample = iteration >= benchmark.warmups;
        const sample_index = iteration -| benchmark.warmups;
        const keep_artifact = is_sample and sample_index + 1 == benchmark.samples and
            options.proof_temporary != null;
        const path = if (keep_artifact)
            try allocator.dupe(u8, options.proof_temporary.?)
        else
            try std.fmt.allocPrint(
                allocator,
                ".stwo-zig-riscv-guest-bench-{d}-{d}.stw",
                .{ run_nonce, iteration },
            );
        defer allocator.free(path);
        defer if (!keep_artifact) std.fs.cwd().deleteFile(path) catch {};

        var timer = try std.time.Timer.start();
        const report_raw = try runProve(
            Engine,
            backend,
            allocator,
            elf_path,
            input_path,
            .{
                .backend = options.backend,
                .protocol = options.protocol,
                .mode = .prove,
                .experimental = options.experimental,
                .proof_temporary = @as(?[]const u8, path),
                .proof_report_path = if (keep_artifact) options.proof_report_path else null,
            },
            process_identity,
            if (benchmark.profiled and is_sample) sample_index else null,
        );
        defer allocator.free(report_raw);
        const elapsed = seconds(timer.read());
        var parsed = try std.json.parseFromSlice(ProveReport, allocator, report_raw, .{
            .ignore_unknown_fields = false,
            .allocate = .alloc_always,
        });
        var parsed_owned = true;
        defer if (parsed_owned) parsed.deinit();
        const should_profile = benchmark.profiled and is_sample;
        const report = &parsed.value;
        const validated = try benchmark_report.validateProveReport(report, .{
            .schema = benchmark_report.proveSchema(should_profile),
            .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
            .experimental = options.experimental,
            .implementation_commit = build_identity.implementation_commit,
            .implementation_dirty = build_identity.implementation_dirty,
            .executable_sha256 = process_identity.executable_sha256,
        });
        if (should_profile) {
            const attempt: ?*const verified_request_attempt.Attempt =
                if (report.profiled_attempt) |*value| value else null;
            try verified_request_attempt.requireProfiled(attempt, sample_index);
        } else if (report.profiled_attempt != null) {
            return error.UnexpectedProfiledVerifiedRequestAttempt;
        }
        statement_digest = validated.statement;
        if (transcript_digest) |expected| {
            if (!std.mem.eql(u8, &expected, &validated.transcript_state))
                return error.NondeterministicTranscriptState;
        } else transcript_digest = validated.transcript_state;
        total_steps = report.total_steps;
        n_components = report.n_components;

        if (is_sample) {
            sample_seconds[sample_index] = elapsed;
            execution_seconds += report.execution_seconds;
            witness_seconds += report.witness_seconds;
            proving_seconds += report.proving_seconds;
            verification_seconds += report.verification_seconds;
            if (comptime backend == .metal) {
                try telemetry.add(report.resident_polynomial_telemetry orelse
                    return error.MissingResidentPolynomialTelemetry);
            } else if (report.resident_polynomial_telemetry != null) {
                return error.UnexpectedResidentPolynomialTelemetry;
            }
            const bytes = try readFileBounded(
                allocator,
                path,
                artifact_limits.max_artifact_bytes,
            );
            defer allocator.free(bytes);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            if (artifact_digest) |expected| {
                if (!std.mem.eql(u8, &expected, &digest))
                    return error.NondeterministicProofArtifact;
            } else artifact_digest = digest;
            if (should_profile) {
                retained[retained_count] = parsed;
                retained_count += 1;
                parsed_owned = false;
            }
        }
    }
    const resources_after = resource_usage.capture();
    const resources = resource_usage.report(resources_before, resources_after);
    if (benchmark.profiled and retained_count != benchmark.samples)
        return error.IncompleteProfiledVerifiedRequestAttempts;
    if (!benchmark.profiled and retained_count != 0)
        return error.UnexpectedProfiledVerifiedRequestAttempt;

    const profiled_attempts = try allocator.alloc(
        *const verified_request_attempt.Attempt,
        retained_count,
    );
    defer allocator.free(profiled_attempts);
    for (retained[0..retained_count], profiled_attempts) |*report, *slot|
        slot.* = if (report.value.profiled_attempt) |*attempt| attempt else unreachable;
    var exact_work_count: usize = 0;
    for (profiled_attempts) |attempt| {
        if (attempt.work_profile != null) exact_work_count += 1;
    }
    if (exact_work_count != 0 and exact_work_count != profiled_attempts.len)
        return error.MixedExactWorkProfileSchemas;

    const denominator = @as(f64, @floatFromInt(benchmark.samples));
    const sorted = try allocator.dupe(f64, sample_seconds);
    defer allocator.free(sorted);
    std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
    const statement_hex = std.fmt.bytesToHex(statement_digest, .lower);
    const artifact_hex = std.fmt.bytesToHex(artifact_digest.?, .lower);
    const transcript_hex = std.fmt.bytesToHex(transcript_digest.?, .lower);
    const executable_hex = std.fmt.bytesToHex(process_identity.executable_sha256, .lower);
    const exact_work = profiled_attempts.len != 0 and
        exact_work_count == profiled_attempts.len;
    const report = BenchmarkReport{
        .schema = if (benchmark.profiled)
            if (exact_work)
                verified_request_attempt.EXACT_WORK_PROFILED_BENCHMARK_SCHEMA
            else
                verified_request_attempt.PROFILED_BENCHMARK_SCHEMA
        else
            benchmark_report.NATIVE_BENCHMARK_SCHEMA,
        .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
        .experimental = options.experimental,
        .profiled = benchmark.profiled,
        .recursion_enabled = false,
        .warmups = benchmark.warmups,
        .samples = benchmark.samples,
        .verified_samples = benchmark.samples,
        .total_steps = total_steps,
        .n_components = n_components,
        .median_seconds = sorted[sorted.len / 2],
        .throughput_mhz = @as(f64, @floatFromInt(total_steps)) /
            sorted[sorted.len / 2] / 1_000_000.0,
        .mean_execution_seconds = execution_seconds / denominator,
        .mean_witness_seconds = witness_seconds / denominator,
        .mean_proving_seconds = proving_seconds / denominator,
        .mean_verification_seconds = verification_seconds / denominator,
        .sample_seconds = sample_seconds,
        .statement_sha256 = &statement_hex,
        .transcript_state_blake2s = &transcript_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = &executable_hex,
        .artifact_sha256 = &artifact_hex,
        .proof_path = options.proof_report_path,
        .resources = resources,
        .resident_polynomial_telemetry = if (comptime backend == .metal) telemetry else null,
        .timing_authority = if (benchmark.profiled) .{} else null,
        .verified_request_attempts = if (benchmark.profiled) profiled_attempts else null,
    };
    return std.json.Stringify.valueAlloc(allocator, report, .{
        .emit_null_optional_fields = false,
    });
}

const OwnedPublicData = struct {
    input_words: []u32,
    output_words: []stwo.frontends.riscv.air.public_data.OutputWord,
    value: stwo.frontends.riscv.air.public_data.PublicData,

    fn init(
        allocator: std.mem.Allocator,
        result: *const stwo.frontends.riscv.runner.RunResult,
    ) !OwnedPublicData {
        const public_data = stwo.frontends.riscv.air.public_data;
        const input_words = try public_data.packInputWords(allocator, result.input);
        errdefer allocator.free(input_words);
        const output_words = try allocator.alloc(public_data.OutputWord, result.output_words.len);
        errdefer allocator.free(output_words);
        for (output_words, result.output_words) |*destination, source| destination.* = .{
            .addr = source.addr,
            .value = source.value,
            .clock = source.clock,
        };
        return .{
            .input_words = input_words,
            .output_words = output_words,
            .value = .{
                .initial_pc = result.initial_pc,
                .final_pc = result.final_pc,
                .clock = std.math.cast(u32, result.step_count) orelse
                    return error.ExecutionClockOutOfRange,
                .initial_regs = result.initial_regs,
                .final_regs = result.final_regs,
                .reg_last_clock = result.state_chain_tracker.reg_last_clk,
                .program_root = null,
                .initial_rw_root = null,
                .final_rw_root = null,
                .completion = try public_data.completionFromRun(result.*),
                .io_entries = .{
                    .input_start = result.input_start,
                    .input_len = std.math.cast(u32, result.input.len) orelse
                        return error.InputLengthOutOfRange,
                    .input_words = input_words,
                    .output_len = result.output_len,
                    .output_len_addr = result.output_len_addr,
                    .output_data_addr = result.output_data_addr,
                    .output_words = output_words,
                },
            },
        };
    }

    fn deinit(self: *OwnedPublicData, allocator: std.mem.Allocator) void {
        allocator.free(self.input_words);
        allocator.free(self.output_words);
        self.* = undefined;
    }
};

fn profileEngine(comptime backend: anytype) type {
    return if (backend == .cpu)
        stwo.integrations.riscv_cpu.CpuProverEngine
    else
        stwo.integrations.riscv_metal.guest_precompile.AuthenticatedProfileEngine;
}

fn guestIntegration(comptime backend: anytype) type {
    if (backend != .metal) @compileError("Metal guest integration requested for CPU");
    return stwo.integrations.riscv_metal.guest_precompile;
}

fn readFileBounded(
    allocator: std.mem.Allocator,
    path: []const u8,
    maximum: usize,
) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size > maximum)
        return error.ArtifactResourceLimitExceeded;
    const length = std.math.cast(usize, stat.size) orelse
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readAll(bytes) != bytes.len) return error.UnexpectedEndOfFile;
    var trailing: [1]u8 = undefined;
    if (try file.read(&trailing) != 0) return error.ArtifactChangedDuringRead;
    return bytes;
}

test "guest profile publication constants match frontend authority" {
    try std.testing.expectEqual(
        stwo.frontends.riscv.prover_mod.MAX_EXECUTION_STEPS,
        maximum_profile_steps,
    );
    try std.testing.expectEqual(@as(usize, 1) << 24, maximum_profile_steps);
    try std.testing.expectEqualStrings(
        stwo.frontends.riscv.isa.execution_profile.poseidon2_name,
        identity.PROFILE_IDENTITY,
    );
    try std.testing.expectEqualSlices(
        u8,
        &stwo.frontends.riscv.air.guest_precompile.manifest.canonical_digest_golden,
        &identity.manifestDigest(),
    );
}
