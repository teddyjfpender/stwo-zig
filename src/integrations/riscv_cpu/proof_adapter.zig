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
const transcript_state = @import("proof_adapter/transcript_state.zig");
const verify_receipt = @import("proof_adapter/verify_receipt.zig");
const wire_arena = @import("proof_adapter/wire_arena.zig");
const wire_reconstruct = @import("proof_adapter/wire_reconstruct.zig");
const resource_usage = @import("resource_usage.zig");

const WireArena = wire_arena.WireArena;

pub const AdapterError = error{AdapterNotReleaseGated};

pub const PENDING_DIAGNOSTIC =
    "RISC-V adapter: staged only; the formal release contract is not yet fully satisfied";

pub const Benchmark = struct {
    warmups: usize,
    samples: usize,
    profiled: bool,
};

pub const Backend = enum { cpu, metal, unavailable_device };
pub const Protocol = enum { secure, functional, smoke };

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
pub fn run(
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
) ![]u8 {
    try capabilities.requireAdmission(options.experimental);
    if (options.backend != .cpu) return error.AdapterNotReleaseGated;
    const process_identity = try artifact_validation.measureProcessIdentity(allocator);
    return switch (options.mode) {
        .prove => runProve(allocator, elf_path, input_path, options, process_identity),
        .bench => |benchmark| runBenchmark(
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
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
    process_identity: ProcessIdentity,
) ![]u8 {
    const proof_temporary = options.proof_temporary orelse return error.AdapterNotReleaseGated;
    var total_timer = try std.time.Timer.start();

    const runner = stwo.frontends.riscv.runner;
    const prover = stwo.frontends.riscv.prover_mod;
    const riscv_cpu = stwo.integrations.riscv_cpu;
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

    var execution_timer = try std.time.Timer.start();
    // The production CLI always enforces the symbol-bearing zkVM ABI. The
    // compatibility runner deliberately accepts older, undeclared programs and
    // must never become an empty-input bypass around this boundary.
    var run_result = try runner.runWithInput(allocator, elf_bytes, input_bytes, 10_000_000);
    defer run_result.deinit();
    if (run_result.completion_reason != .halt_flag and
        run_result.completion_reason != .self_loop)
        return error.InvalidReleaseCompletion;
    const execution_seconds = seconds(execution_timer.read());

    const config = stagedPcsConfig(options.protocol);
    const pd_mod = stwo.frontends.riscv.air.public_data;
    const input_words = try pd_mod.packInputWords(allocator, run_result.input);
    defer allocator.free(input_words);
    const out_words = try allocator.alloc(pd_mod.OutputWord, run_result.output_words.len);
    defer allocator.free(out_words);
    for (run_result.output_words, 0..) |word, i| out_words[i] = .{
        .addr = word.addr,
        .value = word.value,
        .clock = word.clock,
    };
    var recorder = stwo.prover.stage_profile.Recorder.init(
        allocator,
        @tagName(@import("builtin").mode),
        "sail_rv32im_zkvm_v1",
    );
    defer recorder.deinit();
    var proving_timer = try std.time.Timer.start();
    var prove_channel = riscv_cpu.CpuProverEngine.Channel{};
    var output = try prover.proveRiscVWithEngineAndPublicDataUsingChannel(
        riscv_cpu.CpuProverEngine,
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
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    const witness_seconds = witnessSeconds(profile.stages);
    const proving_seconds = @max(0.0, proving_with_witness_seconds - witness_seconds);
    var proof_owned = true;
    defer if (proof_owned) output.proof.deinit(allocator);

    // Serialize the proof FIRST: verification consumes ownership of it.
    var proof_bytes: std.ArrayList(u8) = .{};
    defer proof_bytes.deinit(allocator);
    try stwo.interop.postcard.serializeProof(
        prover.Hasher,
        proof_bytes.writer(allocator),
        output.proof,
    );

    // Independent in-process verification BEFORE anything is written.
    // The verifier consumes the proof on both success and failure.
    var verification_timer = try std.time.Timer.start();
    proof_owned = false;
    var verify_channel = riscv_cpu.CpuProverEngine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        riscv_cpu.CpuProverEngine,
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
    const verification_seconds = seconds(verification_timer.read());
    const proof_hex = try allocator.alloc(u8, proof_bytes.items.len * 2);
    defer allocator.free(proof_hex);
    for (proof_bytes.items, 0..) |byte, i| {
        _ = std.fmt.bufPrint(proof_hex[i * 2 ..][0..2], "{x:0>2}", .{byte}) catch unreachable;
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
        .backend = "cpu",
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

    return std.fmt.allocPrint(
        allocator,
        "{{\"schema\":\"riscv_prove_v1\",\"release_status\":\"{s}\"," ++
            "\"experimental\":{},\"verified_in_process\":true," ++
            "\"total_steps\":{d},\"n_components\":{d}," ++
            "\"execution_seconds\":{d},\"witness_seconds\":{d}," ++
            "\"proving_seconds\":{d},\"verification_seconds\":{d}," ++
            "\"total_seconds\":{d}," ++
            "\"statement_sha256\":\"{s}\"," ++
            "\"transcript_state_blake2s\":\"{s}\"," ++
            "\"implementation_commit\":\"{s}\",\"implementation_dirty\":{}," ++
            "\"executable_sha256\":\"{s}\",\"proof_path\":\"{s}\"}}",
        .{
            artifact_mod.RELEASE_STATUS,
            options.experimental,
            output.statement.total_steps,
            output.statement.n_components,
            execution_seconds,
            witness_seconds,
            proving_seconds,
            verification_seconds,
            seconds(total_timer.read()),
            &statement_digest_hex,
            &transcript_state_digest_hex,
            build_identity.implementation_commit,
            build_identity.implementation_dirty,
            &executable_digest_hex,
            options.proof_report_path orelse proof_temporary,
        },
    );
}

fn seconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
}

fn witnessSeconds(nodes: []const stwo.prover.stage_profile.StageNode) f64 {
    var total: f64 = 0;
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, "riscv_opcode_trace_generation") or
            std.mem.eql(u8, node.id, "riscv_infrastructure_trace_generation"))
            total += node.seconds;
        if (node.children) |children| total += witnessSeconds(children);
    }
    return total;
}

const ProveReport = struct {
    total_steps: u32,
    n_components: u32,
    execution_seconds: f64,
    witness_seconds: f64,
    proving_seconds: f64,
    verification_seconds: f64,
    total_seconds: f64,
    statement_sha256: []const u8,
    transcript_state_blake2s: []const u8,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: []const u8,
};

fn runBenchmark(
    allocator: std.mem.Allocator,
    elf_path: []const u8,
    input_path: ?[]const u8,
    options: Options,
    benchmark: Benchmark,
    process_identity: ProcessIdentity,
) ![]u8 {
    const sample_seconds = try allocator.alloc(f64, benchmark.samples);
    defer allocator.free(sample_seconds);
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
        const report_raw = try runProve(allocator, elf_path, input_path, .{
            .backend = options.backend,
            .protocol = options.protocol,
            .mode = .prove,
            .experimental = options.experimental,
            .proof_temporary = path,
            .proof_report_path = if (keep_artifact) options.proof_report_path else null,
        }, process_identity);
        defer allocator.free(report_raw);
        const elapsed = seconds(timer.read());

        var parsed = try std.json.parseFromSlice(ProveReport, allocator, report_raw, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        defer parsed.deinit();
        const report = parsed.value;
        if (report.statement_sha256.len != statement_digest.len * 2)
            return error.InvalidStatementDigest;
        _ = std.fmt.hexToBytes(&statement_digest, report.statement_sha256) catch
            return error.InvalidStatementDigest;
        var current_transcript_state_digest: [32]u8 = undefined;
        if (report.transcript_state_blake2s.len != current_transcript_state_digest.len * 2)
            return error.InvalidTranscriptStateDigest;
        _ = std.fmt.hexToBytes(
            &current_transcript_state_digest,
            report.transcript_state_blake2s,
        ) catch return error.InvalidTranscriptStateDigest;
        if (!std.mem.eql(u8, report.implementation_commit, build_identity.implementation_commit) or
            report.implementation_dirty != build_identity.implementation_dirty)
            return error.ImplementationIdentityMismatch;
        const executable_hex = std.fmt.bytesToHex(process_identity.executable_sha256, .lower);
        if (!std.mem.eql(u8, report.executable_sha256, &executable_hex))
            return error.ExecutableIdentityMismatch;
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
    const report = .{
        .schema = "riscv_proof_v2",
        .release_status = stwo.interop.riscv_artifact.RELEASE_STATUS,
        .mode = "bench",
        .experimental = options.experimental,
        .profiled = benchmark.profiled,
        .warmups = benchmark.warmups,
        .samples = benchmark.samples,
        .verified_samples = benchmark.samples,
        .total_steps = total_steps,
        .n_components = n_components,
        .throughput_numerator = "vm_steps",
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
    };
    return std.json.Stringify.valueAlloc(allocator, report, .{});
}

fn stagedPcsConfig(protocol: Protocol) stwo.core.pcs.PcsConfig {
    return switch (protocol) {
        .secure => .{
            .pow_bits = 26,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 70,
            },
        },
        .functional => .{
            .pow_bits = 10,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
            },
        },
        .smoke => .{
            .pow_bits = 0,
            .fri_config = .{
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
            },
        },
    };
}

/// Cryptographically verifies a staged artifact: structural validation,
/// statement/claim/proof reconstruction from the wire, then the full
/// verifier including global LogUp cancellation. Acceptance is reported
/// with the artifact's own release status so staged verification can never
/// be mistaken for promotion.
pub fn verifyArtifact(
    allocator: std.mem.Allocator,
    artifact: stwo.interop.riscv_artifact.Artifact,
    requested_policy: Protocol,
    expected_statement_digest: [32]u8,
    elf_path: []const u8,
) !void {
    const artifact_mod = stwo.interop.riscv_artifact;
    const prover = stwo.frontends.riscv.prover_mod;
    const riscv_cpu = stwo.integrations.riscv_cpu;

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
    var verify_channel = riscv_cpu.CpuProverEngine.Channel{};
    try prover.verifyRiscVWithEngineUsingChannel(
        riscv_cpu.CpuProverEngine,
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

test "adapter preserves the complete sampled benchmark contract" {
    const options = Options{
        .backend = .cpu,
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
        run(std.testing.allocator, "guest.elf", "input.bin", options),
    );
}

test "adapter PCS profiles satisfy their advertised artifact policies" {
    const cases = [_]struct {
        protocol: Protocol,
        pow_bits: u32,
        n_queries: usize,
    }{
        .{ .protocol = .secure, .pow_bits = 26, .n_queries = 70 },
        .{ .protocol = .functional, .pow_bits = 10, .n_queries = 3 },
        .{ .protocol = .smoke, .pow_bits = 0, .n_queries = 3 },
    };
    for (cases) |case| {
        const config = stagedPcsConfig(case.protocol);
        try std.testing.expectEqual(case.pow_bits, config.pow_bits);
        try std.testing.expectEqual(case.n_queries, config.fri_config.n_queries);
    }
}

test "staged verifier binds build and witness-layout provenance" {
    const artifact = stwo.interop.riscv_artifact;
    const layout = std.fmt.bytesToHex(stwo.frontends.riscv.witness_layout.digest(), .lower);
    var provenance = artifact.ProvenanceWire{
        .oracle_repository = artifact.ORACLE_REPOSITORY,
        .oracle_commit = artifact.ORACLE_COMMIT,
        .implementation_repository = artifact.IMPLEMENTATION_REPOSITORY,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .witness_layout_sha256 = &layout,
    };
    try artifact_validation.validateLocalProvenance(provenance);

    provenance.implementation_commit = "00" ** 20;
    try std.testing.expectError(
        error.ImplementationIdentityMismatch,
        artifact_validation.validateLocalProvenance(provenance),
    );
    provenance.implementation_commit = build_identity.implementation_commit;
    provenance.witness_layout_sha256 = "00" ** 32;
    try std.testing.expectError(
        error.WitnessLayoutMismatch,
        artifact_validation.validateLocalProvenance(provenance),
    );
}

test "wire arena rolls back every partial allocation" {
    const prover = stwo.frontends.riscv.prover_mod;
    const public_data = stwo.frontends.riscv.air.public_data;
    const input_words = [_]u32{7};
    const output_words = [_]public_data.OutputWord{.{ .addr = 8, .value = 9, .clock = 10 }};
    var statement: prover.RiscVStatement = .{
        .n_components = 1,
        .component_descs = undefined,
        .initial_pc = 4,
        .final_pc = 8,
        .total_steps = 1,
        .public_data = .{
            .initial_pc = 4,
            .final_pc = 8,
            .clock = 1,
            .initial_regs = .{0} ** 32,
            .final_regs = .{0} ** 32,
            .reg_last_clock = .{0} ** 32,
            .program_root = null,
            .initial_rw_root = null,
            .final_rw_root = null,
            .io_entries = .{
                .input_start = 0,
                .input_len = 4,
                .input_words = &input_words,
                .output_len = 4,
                .output_len_addr = 8,
                .output_data_addr = 12,
                .output_words = &output_words,
            },
        },
        .n_infra = 1,
        .infra_descs = undefined,
    };
    statement.component_descs[0] = .{
        .family = .base_alu_imm,
        .log_size = 1,
        .n_rows = 1,
        .n_columns = 4,
    };
    statement.infra_descs[0] = .{
        .kind = .program,
        .log_size = 1,
        .n_rows = 1,
        .n_columns = 4,
    };
    var claim = prover.RiscVInteractionClaim.initZero();
    claim.n_components = 1;
    claim.n_infra = 1;
    const output = .{ .statement = statement, .interaction_claim = claim };

    for (0..8) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        try std.testing.expectError(
            error.OutOfMemory,
            WireArena.init(failing.allocator(), output),
        );
        try std.testing.expect(failing.has_induced_failure);
        try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
    }
}
