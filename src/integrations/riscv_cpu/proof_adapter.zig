//! Sail-authoritative RV32IM ELF adapter seam behind the production proof CLI.
//!
//! The adapter is deliberately fail-closed: `proveElf` is the one call site
//! the CLI routes `--elf` runs through, and it returns
//! `error.AdapterNotReleaseGated` until the RV32IM AIR and public I/O binding
//! pass the release gate. Wiring the real prover is a one-function change
//! here; the focused capability authority flips only at that moment.
//!
//! The adapter is engine-parameterised: `runWithEngine` and
//! `verifyArtifactWithEngine` take the prover engine and the backend tag as
//! comptime parameters, mirroring `tools/riscv/bench/runner.mainWithEngine`,
//! so one implementation of the atomic publication path, the determinism
//! checks and the transcript-digest cross-check serves every backend. There is
//! deliberately no second copy of this file per backend: two adapters that must
//! not drift is precisely the failure mode this seam exists to prevent.
//! `run`/`verifyArtifact` remain as the facade-default bindings so the existing
//! focused and aggregate CPU call sites are untouched.

const std = @import("std");
const stwo = @import("stwo");
const capabilities = @import("riscv_cpu_capabilities");
const build_identity = @import("build_identity");
const artifact_validation = @import("proof_adapter/artifact_validation.zig");
const benchmark_report = @import("proof_adapter/benchmark_report.zig");
const pcs_profile = @import("proof_adapter/pcs_profile.zig");
const transcript_state = @import("proof_adapter/transcript_state.zig");
const verified_request_attempt = @import("proof_adapter/verified_request_attempt.zig");
const verify_receipt = @import("proof_adapter/verify_receipt.zig");
const wire_arena = @import("proof_adapter/wire_arena.zig");
const wire_reconstruct = @import("proof_adapter/wire_reconstruct.zig");
const resource_usage = @import("resource_usage.zig");

const WireArena = wire_arena.WireArena;
const BenchmarkReport = benchmark_report.BenchmarkReport;
const ProveReport = benchmark_report.ProveReport;
const ResidentPolynomialTelemetry = benchmark_report.ResidentPolynomialTelemetry;
const seconds = benchmark_report.seconds;
const stagedPcsConfig = pcs_profile.select;
const witnessSeconds = benchmark_report.witnessSeconds;

pub const AdapterError = error{AdapterNotReleaseGated};

pub const PENDING_DIAGNOSTIC =
    "RISC-V adapter: staged only; the formal release contract is not yet fully satisfied";

pub const Benchmark = struct {
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const Backend = enum { cpu, metal, unavailable_device };
pub const Protocol = pcs_profile.Protocol;

pub const Mode = union(enum) {
    prove,
    bench: Benchmark,
};

pub const Options = struct {
    backend: Backend,
    protocol: Protocol,
    mode: Mode,
    experimental: bool,
    /// Sibling temporary path owned and published by the CLI transaction.
    proof_temporary: ?[]const u8,
    /// Final path recorded in the report; the adapter never publishes it.
    proof_report_path: ?[]const u8,
};

const ProcessIdentity = artifact_validation.ProcessIdentity;

/// Runs the staged ELF adapter and returns an owned machine-readable report.
///
/// Keeping publication outside the adapter gives Native and RISC-V workloads
/// identical exclusive-output and rollback behavior when the release gate is
/// eventually opened.
/// Drive one proving transaction on `Engine`.
///
/// `Engine` and `backend` are comptime so a product binds exactly one engine and
/// links exactly one commitment backend -- the CPU product must not acquire a
/// Metal link edge, which its own closure gate forbids. `@tagName(.cpu) == "cpu"`,
/// so a CPU artifact produced through this generic path is byte-identical to one
/// produced before the parameterisation.
pub fn run(
    comptime Engine: type,
    comptime backend: Backend,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
) ![]u8 {
    comptime stwo.frontends.riscv.prover_mod.assertProverEngine(Engine);
    comptime std.debug.assert(backend != .unavailable_device);
    try capabilities.requireAdmission(options.experimental);
    if (options.backend != backend) return error.AdapterNotReleaseGated;
    // Build pipelines and libraries before the first timed sample. This does not
    // distort `resources`: the footprint is an absolute process-lifetime peak
    // read from the *after* snapshot.
    if (comptime @hasDecl(Engine, "warmup")) try Engine.warmup();
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
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
    comptime backend: Backend,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
    process_identity: ProcessIdentity,
    profiled_sample_index: ?usize,
) ![]u8 {
    const proof_temporary = options.proof_temporary orelse return error.AdapterNotReleaseGated;
    var total_timer = try std.time.Timer.start();

    const runner = stwo.frontends.riscv.runner;
    const prover = stwo.frontends.riscv.prover_mod;
    const artifact_mod = stwo.interop.riscv_artifact;

    const elf_bytes = try std.fs.cwd().readFileAlloc(allocator, elf_path, 64 * 1024 * 1024);
    defer allocator.free(elf_bytes);
    try runner.elf_loader.validateReleaseAbi(elf_bytes);
    var elf_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(elf_bytes, &elf_digest, .{});

    const input_bytes: []const u8 = if (input_path) |path|
        try std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024 * 1024)
    else
        &.{};
    defer if (input_path != null) allocator.free(@constCast(input_bytes));
    var input_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input_bytes, &input_digest, .{});

    const config = stagedPcsConfig(options.protocol);
    const pd_mod = stwo.frontends.riscv.air.public_data;
    var recorder = stwo.prover.stage_profile.Recorder.initWithOptions(
        allocator,
        @tagName(@import("builtin").mode),
        "sail_rv32im_zkvm_v1",
        .{ .capture_tasks = profiled_sample_index != null },
    );
    defer recorder.deinit();
    const telemetry_before = if (comptime backend == .metal)
        try Engine.telemetrySnapshot()
    else {};

    // The optional monotonic phase clock excludes ELF/input I/O and recorder
    // setup. Its first two boundaries cover guest execution and all subsequent
    // proof work through proof construction; serialization is excluded.
    var execution_timer = try std.time.Timer.start();
    var profile_phase_timer: ?std.time.Timer = if (profiled_sample_index != null)
        try std.time.Timer.start()
    else
        null;
    // The production CLI always enforces the symbol-bearing zkVM ABI. The
    // compatibility runner deliberately accepts older, undeclared programs and
    // must never become an empty-input bypass around this boundary.
    var run_result = try runner.runWithInput(allocator, elf_bytes, input_bytes, 10_000_000);
    defer run_result.deinit();
    // Fail closed on any run the statement cannot bind, through the *one*
    // definition of that rule (`prover.admitRunForProving`). The benchmark
    // runner in `src/tools/riscv/bench/runner.zig` calls the same function: this
    // path used to own a private copy of the completion test, the bench tool had
    // none, and the two drifted until an ECALL-terminated trace reached the
    // prover (issue #152 item 5).
    try prover.admitRunForProving(&run_result);
    const execution_ns = execution_timer.read();
    const execution_seconds = seconds(execution_ns);
    const guest_execution_ns: ?u64 = if (profile_phase_timer) |*timer|
        timer.read()
    else
        null;

    const input_words = try pd_mod.packInputWords(allocator, run_result.input);
    defer allocator.free(input_words);
    const out_words = try allocator.alloc(pd_mod.OutputWord, run_result.output_words.len);
    defer allocator.free(out_words);
    for (run_result.output_words, 0..) |word, i| out_words[i] = .{
        .addr = word.addr,
        .value = word.value,
        .clock = word.clock,
    };
    var proving_timer = try std.time.Timer.start();
    var prove_channel = Engine.Channel{};
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannel(
        Engine,
        allocator,
        config,
        &run_result.execution_trace,
        &run_result.state_chain_tracker,
        &run_result.rw_memory,
        &recorder,
        .{
            .initial_pc = run_result.initial_pc,
            .final_pc = run_result.final_pc,
            .clock = @intCast(run_result.step_count),
            .initial_regs = run_result.initial_regs,
            .final_regs = run_result.final_regs,
            .reg_last_clock = run_result.state_chain_tracker.reg_last_clk,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .completion = try pd_mod.completionFromRun(run_result),
            .io_entries = .{
                .input_start = run_result.input_start,
                .input_len = @intCast(run_result.input.len),
                .input_words = input_words,
                .output_len = run_result.output_len,
                .output_len_addr = run_result.output_len_addr,
                .output_data_addr = run_result.output_data_addr,
                .output_words = out_words,
            },
        },
        &prove_channel,
    );
    defer output.deinitAfterProofMoved(allocator);
    const transcript_state_digest = transcript_state.receiptDigest(
        prove_channel.digestBytes(),
        prove_channel.n_draws,
    );
    const proving_with_witness_seconds = seconds(proving_timer.read());
    const proving_including_witness_ns: ?u64 = if (profile_phase_timer) |*timer|
        std.math.sub(u64, timer.read(), guest_execution_ns.?) catch
            return error.ProfileClockRegression
    else
        null;
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);

    // Serialization is outside the coarse protocol partition. It must still
    // precede native verification because verification consumes the proof.
    var proof_bytes: std.ArrayList(u8) = .{};
    defer proof_bytes.deinit(allocator);
    try stwo.interop.postcard.serializeProof(
        prover.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );

    // Native in-process verification BEFORE anything is written.
    // The verifier consumes the proof on both success and failure.
    var verification_timer = try std.time.Timer.start();
    proof_owned = false;
    var verify_channel = Engine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        config,
        output.statement,
        output.proof,
        output.interaction_claim,
        &verify_channel,
    );
    const verify_transcript_state_digest = transcript_state.receiptDigest(
        verify_channel.digestBytes(),
        verify_channel.n_draws,
    );
    if (!std.mem.eql(u8, &transcript_state_digest, &verify_transcript_state_digest))
        return error.TranscriptStateDigestMismatch;
    const verification_ns = verification_timer.read();
    const verification_seconds = seconds(verification_ns);

    // Everything below is cold receipt/artifact work and is deliberately
    // outside `verified_request_ns`.
    var resident_polynomial_telemetry: ResidentPolynomialTelemetry = .{};
    if (comptime backend == .metal) {
        const telemetry_after = try Engine.telemetrySnapshot();
        const telemetry_delta = telemetry_after.delta(telemetry_before);
        try telemetry_delta.requireResidentRiscPolynomialExecution();
        resident_polynomial_telemetry = ResidentPolynomialTelemetry.fromDelta(
            telemetry_delta,
        );
        resident_polynomial_telemetry.verified_samples_with_dispatch = 1;
    }
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    const witness_seconds = witnessSeconds(profile.stages);
    const proving_seconds = @max(0.0, proving_with_witness_seconds - witness_seconds);

    var profiled_attempt: ?verified_request_attempt.Attempt = if (profiled_sample_index) |index|
        try verified_request_attempt.Attempt.capture(
            allocator,
            index,
            guest_execution_ns.?,
            proving_including_witness_ns.?,
            verification_ns,
            &recorder,
        )
    else
        null;
    defer if (profiled_attempt) |*attempt| attempt.deinit(allocator);
    const encoded_attempt: ?[]u8 = if (profiled_attempt) |attempt|
        try std.json.Stringify.valueAlloc(allocator, attempt, .{})
    else
        null;
    defer if (encoded_attempt) |encoded| allocator.free(encoded);
    if (profiled_sample_index != null) {
        const encoded_profile = try std.json.Stringify.valueAlloc(allocator, profile, .{});
        defer allocator.free(encoded_profile);
        std.log.info("RISC-V stage profile: {s}", .{encoded_profile});
    }

    const proof_hex_len = try std.math.mul(usize, proof_bytes.items.len, 2);
    const proof_hex = try allocator.alloc(u8, proof_hex_len);
    defer allocator.free(proof_hex);
    for (proof_bytes.items, 0..) |byte, i| {
        const hex_index = try std.math.mul(usize, i, 2);
        _ = std.fmt.bufPrint(proof_hex[hex_index..][0..2], "{x:0>2}", .{byte}) catch
            unreachable;
    }

    var wires = try WireArena.init(allocator, &output);
    defer wires.deinit(allocator);
    const elf_digest_hex = std.fmt.bytesToHex(elf_digest, .lower);
    const input_digest_hex = std.fmt.bytesToHex(input_digest, .lower);
    const source = artifact_mod.SourceWire{
        .elf_sha256 = &elf_digest_hex,
        .input_sha256 = &input_digest_hex,
    };
    const pcs_wire = artifact_mod.PcsConfigWire{
        .pow_bits = config.pow_bits,
        .fri_config = .{
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .n_queries = config.fri_config.n_queries,
            .fold_step = config.fri_config.fold_step,
        },
        .lifting_log_size = config.lifting_log_size,
    };
    const layout_digest_hex = std.fmt.bytesToHex(
        stwo.frontends.riscv.witness_layout.digest(),
        .lower,
    );
    const statement_digest = artifact_mod.statementDigest(
        @tagName(options.protocol),
        pcs_wire,
        source,
        wires.statement,
    );
    const statement_digest_hex = std.fmt.bytesToHex(statement_digest, .lower);
    const transcript_state_digest_hex = std.fmt.bytesToHex(transcript_state_digest, .lower);
    const executable_digest_hex = std.fmt.bytesToHex(
        process_identity.executable_sha256,
        .lower,
    );

    try artifact_mod.writeArtifact(allocator, proof_temporary, .{
        .artifact_kind = artifact_mod.ARTIFACT_KIND,
        .schema_version = artifact_mod.SCHEMA_VERSION,
        .exchange_mode = artifact_mod.EXCHANGE_MODE,
        .release_status = artifact_mod.RELEASE_STATUS,
        .generator = artifact_mod.GENERATOR,
        .air = artifact_mod.AIR,
        .backend = @tagName(backend),
        .protocol = @tagName(options.protocol),
        .source = source,
        .provenance = .{
            .oracle_repository = artifact_mod.ORACLE_REPOSITORY,
            .oracle_commit = artifact_mod.ORACLE_COMMIT,
            .implementation_repository = artifact_mod.IMPLEMENTATION_REPOSITORY,
            .implementation_commit = build_identity.implementation_commit,
            .implementation_dirty = build_identity.implementation_dirty,
            .witness_layout_sha256 = &layout_digest_hex,
        },
        .pcs_config = pcs_wire,
        .statement = wires.statement,
        .interaction_claim = wires.claim,
        .proof_bytes_hex = proof_hex,
    });

    const resident_polynomial_telemetry_json: []const u8 = if (comptime backend == .metal)
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
    defer if (comptime backend == .metal)
        allocator.free(resident_polynomial_telemetry_json);
    const profiled_attempt_json: []const u8 = if (encoded_attempt) |encoded|
        try std.fmt.allocPrint(allocator, "\"profiled_attempt\":{s},", .{encoded})
    else
        "";
    defer if (encoded_attempt != null) allocator.free(profiled_attempt_json);

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
            artifact_mod.RELEASE_STATUS,
            options.experimental,
            output.statement.total_steps,
            output.statement.n_components,
            execution_seconds,
            witness_seconds,
            proving_seconds,
            verification_seconds,
            seconds(total_timer.read()),
            resident_polynomial_telemetry_json,
            profiled_attempt_json,
            &statement_digest_hex,
            &transcript_state_digest_hex,
            build_identity.implementation_commit,
            build_identity.implementation_dirty,
            &executable_digest_hex,
            options.proof_report_path orelse proof_temporary,
        },
    );
}

fn runBenchmark(
    comptime Engine: type,
    comptime backend: Backend,
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
    benchmark: Benchmark,
    process_identity: ProcessIdentity,
) ![]u8 {
    const sample_seconds = try allocator.alloc(f64, benchmark.samples);
    defer allocator.free(sample_seconds);
    const retained_profiled_reports = try allocator.alloc(
        std.json.Parsed(ProveReport),
        if (benchmark.profiled) benchmark.samples else 0,
    );
    var retained_profiled_report_count: usize = 0;
    defer {
        for (retained_profiled_reports[0..retained_profiled_report_count]) |*report| {
            report.deinit();
        }
        allocator.free(retained_profiled_reports);
    }
    const run_nonce = std.time.nanoTimestamp();
    var artifact_digest: ?[32]u8 = null;
    var statement_digest: [32]u8 = undefined;
    var total_steps: u32 = 0;
    var n_components: u32 = 0;
    var execution_seconds: f64 = 0;
    var witness_seconds: f64 = 0;
    var proving_seconds: f64 = 0;
    var verification_seconds: f64 = 0;
    var transcript_state_digest: ?[32]u8 = null;
    var resident_polynomial_telemetry: ResidentPolynomialTelemetry = .{};

    const resources_before_warmups = resource_usage.capture();
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
                ".stwo-zig-riscv-bench-{d}-{d}.json",
                .{ run_nonce, iteration },
            );
        defer allocator.free(path);
        defer if (!keep_artifact) std.fs.cwd().deleteFile(path) catch {};

        var timer = try std.time.Timer.start();
        const report_raw = try runProve(Engine, backend, allocator, elf_path, input_path, .{
            .backend = options.backend,
            .protocol = options.protocol,
            .mode = .prove,
            .experimental = options.experimental,
            .proof_temporary = path,
            .proof_report_path = if (keep_artifact) options.proof_report_path else null,
        }, process_identity, if (benchmark.profiled and is_sample) sample_index else null);
        defer allocator.free(report_raw);
        const elapsed = seconds(timer.read());

        var parsed = try std.json.parseFromSlice(ProveReport, allocator, report_raw, .{
            .ignore_unknown_fields = false,
            .allocate = .alloc_always,
        });
        var parsed_owned = true;
        defer if (parsed_owned) parsed.deinit();
        const should_profile_attempt = benchmark.profiled and is_sample;
        const report = &parsed.value;
        const validated = try benchmark_report.validateProveReport(report, .{
            .schema = benchmark_report.proveSchema(should_profile_attempt),
            .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
            .experimental = options.experimental,
            .implementation_commit = build_identity.implementation_commit,
            .implementation_dirty = build_identity.implementation_dirty,
            .executable_sha256 = process_identity.executable_sha256,
        });
        if (should_profile_attempt) {
            const attempt: ?*const verified_request_attempt.Attempt =
                if (report.profiled_attempt) |*value| value else null;
            try verified_request_attempt.requireProfiled(attempt, sample_index);
        } else if (report.profiled_attempt != null) {
            return error.UnexpectedProfiledVerifiedRequestAttempt;
        }
        statement_digest = validated.statement;
        const current_transcript_state_digest = validated.transcript_state;
        if (transcript_state_digest) |expected| {
            if (!std.mem.eql(u8, &expected, &current_transcript_state_digest))
                return error.NondeterministicTranscriptState;
        } else {
            transcript_state_digest = current_transcript_state_digest;
        }
        total_steps = report.total_steps;
        n_components = report.n_components;

        if (is_sample) {
            sample_seconds[sample_index] = elapsed;
            execution_seconds += report.execution_seconds;
            witness_seconds += report.witness_seconds;
            proving_seconds += report.proving_seconds;
            verification_seconds += report.verification_seconds;
            if (comptime backend == .metal) {
                try resident_polynomial_telemetry.add(
                    report.resident_polynomial_telemetry orelse
                        return error.MissingResidentPolynomialTelemetry,
                );
            } else if (report.resident_polynomial_telemetry != null) {
                return error.UnexpectedResidentPolynomialTelemetry;
            }

            const artifact_bytes = try std.fs.cwd().readFileAlloc(
                allocator,
                path,
                stwo.interop.riscv_artifact.MAX_ARTIFACT_BYTES,
            );
            defer allocator.free(artifact_bytes);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(artifact_bytes, &digest, .{});
            if (artifact_digest) |expected| {
                if (!std.mem.eql(u8, &expected, &digest))
                    return error.NondeterministicProofArtifact;
            } else {
                artifact_digest = digest;
            }
            if (should_profile_attempt) {
                retained_profiled_reports[retained_profiled_report_count] = parsed;
                retained_profiled_report_count += 1;
                parsed_owned = false;
            }
        }
    }
    const resources_after_verified_samples = resource_usage.capture();
    const resources = resource_usage.report(
        resources_before_warmups,
        resources_after_verified_samples,
    );

    const denominator = @as(f64, @floatFromInt(benchmark.samples));
    const sorted = try allocator.dupe(f64, sample_seconds);
    defer allocator.free(sorted);
    std.mem.sort(f64, sorted, {}, std.sort.asc(f64));
    const median_seconds = sorted[sorted.len / 2];
    const statement_hex = std.fmt.bytesToHex(statement_digest, .lower);
    const artifact_hex = std.fmt.bytesToHex(artifact_digest.?, .lower);
    const transcript_state_hex = std.fmt.bytesToHex(transcript_state_digest.?, .lower);
    const executable_hex = std.fmt.bytesToHex(process_identity.executable_sha256, .lower);
    const report_resident_polynomial_telemetry: ?ResidentPolynomialTelemetry =
        if (comptime backend == .metal) resident_polynomial_telemetry else null;
    if (benchmark.profiled and retained_profiled_report_count != benchmark.samples) {
        return error.IncompleteProfiledVerifiedRequestAttempts;
    }
    if (!benchmark.profiled and retained_profiled_report_count != 0) {
        return error.UnexpectedProfiledVerifiedRequestAttempt;
    }
    const profiled_attempts = try allocator.alloc(
        *const verified_request_attempt.Attempt,
        retained_profiled_report_count,
    );
    defer allocator.free(profiled_attempts);
    // Borrowed views are valid through stringify: their parsed arenas remain
    // retained and are deinitialized only by the earlier function-scope defer.
    for (retained_profiled_reports[0..retained_profiled_report_count], profiled_attempts) |
        *retained,
        *slot,
    | {
        slot.* = if (retained.value.profiled_attempt) |*attempt| attempt else unreachable;
    }
    const report = BenchmarkReport{
        .schema = if (benchmark.profiled)
            verified_request_attempt.PROFILED_BENCHMARK_SCHEMA
        else
            "riscv_proof_v2",
        .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
        .experimental = options.experimental,
        .profiled = benchmark.profiled,
        .warmups = benchmark.warmups,
        .samples = benchmark.samples,
        .verified_samples = benchmark.samples,
        .total_steps = total_steps,
        .n_components = n_components,
        .median_seconds = median_seconds,
        .throughput_mhz = @as(f64, @floatFromInt(total_steps)) / median_seconds / 1_000_000.0,
        .mean_execution_seconds = execution_seconds / denominator,
        .mean_witness_seconds = witness_seconds / denominator,
        .mean_proving_seconds = proving_seconds / denominator,
        .mean_verification_seconds = verification_seconds / denominator,
        .sample_seconds = sample_seconds,
        .statement_sha256 = &statement_hex,
        .transcript_state_blake2s = &transcript_state_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = &executable_hex,
        .artifact_sha256 = &artifact_hex,
        .proof_path = options.proof_report_path,
        .resources = resources,
        .resident_polynomial_telemetry = report_resident_polynomial_telemetry,
        .timing_authority = if (benchmark.profiled) .{} else null,
        .verified_request_attempts = if (benchmark.profiled) profiled_attempts else null,
    };
    return std.json.Stringify.valueAlloc(allocator, report, .{
        .emit_null_optional_fields = false,
    });
}

/// Cryptographically verifies a staged artifact: structural validation,
/// statement/claim/proof reconstruction from the wire, then the full
/// verifier including global LogUp cancellation. Acceptance is reported
/// with the artifact's own release status so staged verification can never
/// be mistaken for promotion.
pub fn verifyArtifact(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    requested_policy: Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
) !void {
    const artifact_mod = stwo.interop.riscv_artifact;
    const prover = stwo.frontends.riscv.prover_mod;

    try artifact_mod.validateForPolicy(artifact, switch (requested_policy) {
        .secure => .secure,
        .functional => .functional,
        .smoke => .smoke,
    });
    try artifact_validation.validateLocalProvenance(artifact.provenance);
    try artifact_validation.validateElfBinding(allocator, artifact, elf_path);
    const actual_statement_digest = artifact_mod.statementDigest(
        artifact.protocol,
        artifact.pcs_config,
        artifact.source,
        artifact.statement,
    );
    if (!std.mem.eql(u8, &expected_statement_digest, &actual_statement_digest))
        return error.StatementDigestMismatch;

    var reconstructed = try wire_reconstruct.Reconstruction.init(allocator, artifact);
    defer reconstructed.deinit(allocator);

    if (artifact.proof_bytes_hex.len % 2 != 0) return error.InvalidArtifact;
    const proof_raw = try allocator.alloc(u8, artifact.proof_bytes_hex.len / 2);
    defer allocator.free(proof_raw);
    _ = std.fmt.hexToBytes(proof_raw, artifact.proof_bytes_hex) catch
        return error.InvalidArtifact;
    try stwo.interop.postcard.proof_preflight.validate(
        proof_raw,
        try artifact_validation.proofPreflightShape(artifact),
    );
    var stream = std.io.fixedBufferStream(proof_raw);
    var proof = try stwo.interop.postcard.deserializeProof(
        prover.Hasher,
        allocator,
        stream.reader(),
    );
    if (stream.pos != proof_raw.len) {
        proof.deinit(allocator);
        return error.InvalidArtifact;
    }

    const config = @TypeOf(stagedPcsConfig(.secure)){
        .pow_bits = artifact.pcs_config.pow_bits,
        .fri_config = .{
            .log_blowup_factor = artifact.pcs_config.fri_config.log_blowup_factor,
            .log_last_layer_degree_bound = artifact.pcs_config.fri_config.log_last_layer_degree_bound,
            .n_queries = artifact.pcs_config.fri_config.n_queries,
        },
    };
    if (!artifact_validation.pcsConfigsEqual(config, proof.commitment_scheme_proof.config)) {
        proof.deinit(allocator);
        return error.ProofConfigMismatch;
    }
    var verify_channel = Engine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        Engine,
        allocator,
        config,
        reconstructed.statement,
        proof,
        &reconstructed.claim,
        &verify_channel,
    );

    var proof_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(proof_raw, &proof_digest, .{});
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    const receipt = try verify_receipt.encode(allocator, .{
        .artifact_kind = artifact.artifact_kind,
        .artifact_schema_version = artifact.schema_version,
        .release_status = artifact.release_status,
        .security_policy = @tagName(requested_policy),
        .statement_sha256 = actual_statement_digest,
        .proof_bytes = proof_raw.len,
        .proof_sha256 = proof_digest,
        .transcript_state_blake2s = transcript_state.receiptDigest(
            verify_channel.digestBytes(),
            verify_channel.n_draws,
        ),
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = process_identity.executable_sha256,
    });
    defer allocator.free(receipt);
    try std.fs.File.stdout().writeAll(receipt);
    try std.fs.File.stdout().writeAll("\n");
}

/// The engine this module's own tests exercise, resolved from whichever product
/// facade compiled them. The tests must not name a concrete integration package:
/// this file is a shared seam, and when it is compiled as a test root inside the
/// Metal product `stwo.integrations.riscv_cpu` does not exist to be resolved.
///
/// Each focused facade declares exactly one RISC-V integration --
/// `src/stwo_riscv_cpu.zig` declares only `riscv_cpu` and
/// `src/products/riscv_metal/root.zig` declares only `riscv_metal` -- so
/// `@hasDecl` is a total discriminator here rather than a feature probe. The
/// condition is comptime-known, so only the branch that resolves is analysed and
/// the absent facade member is never named in the compiled product. The
/// aggregate `src/stwo.zig` facade routes through `integrations/mod.zig`, which
/// declares `riscv_cpu`, and so takes the same branch as the CPU product.
const TestEngine = if (@hasDecl(stwo.integrations, "riscv_cpu"))
    stwo.integrations.riscv_cpu.CpuProverEngine
else
    stwo.integrations.riscv_metal.MetalProverEngine;

/// The backend tag `TestEngine` commits to. `run` rejects an `Options.backend`
/// that disagrees with its comptime `backend` parameter, so the two must be
/// selected together.
const test_backend: Backend = if (@hasDecl(stwo.integrations, "riscv_cpu")) .cpu else .metal;

test "adapter preserves the complete sampled benchmark contract" {
    const options = Options{
        .backend = test_backend,
        .protocol = .functional,
        .mode = .{ .bench = .{ .warmups = 3, .samples = 7, .profiled = true } },
        .experimental = !capabilities.adapter_release_gated,
        .proof_temporary = "proof.tmp",
        .proof_report_path = "proof.json",
    };
    try std.testing.expectEqual(@as(usize, 3), options.mode.bench.warmups);
    try std.testing.expectEqual(@as(usize, 7), options.mode.bench.samples);
    try std.testing.expect(options.mode.bench.profiled);
    try std.testing.expectError(
        error.FileNotFound,
        run(TestEngine, test_backend, std.testing.allocator, "guest.elf", "input.bin", options),
    );
}

test {
    _ = @import("proof_adapter/provenance_test.zig");
    _ = @import("proof_adapter/staged_pcs_profile_test.zig");
    _ = @import("proof_adapter/verified_request_binding_test.zig");
    _ = @import("proof_adapter/wire_arena_allocation_test.zig");
}

test "adapter fail-closes through the shared run-admission gate" {
    const prover = stwo.frontends.riscv.prover_mod;
    // Every completion reason but the two proof-bearing ones must be refused,
    // and the refusal must come from the gate this adapter calls rather than
    // from a private copy. `runProve` invokes `admitRunForProving` directly, so
    // a regression here is a regression in what the adapter enforces.
    for (std.enums.values(stwo.frontends.riscv.runner.CompletionReason)) |reason| {
        const provable = reason == .halt_flag or reason == .self_loop;
        const rejection = prover.classifyCompletion(reason);
        try std.testing.expectEqual(provable, rejection == null);
        if (rejection) |value| try std.testing.expectEqual(
            prover.RunAdmissionError.UnprovableCompletion,
            value.toError(),
        );
    }
}
