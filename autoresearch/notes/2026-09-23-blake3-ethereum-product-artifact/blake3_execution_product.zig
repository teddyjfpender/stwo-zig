//! Product transaction for full-width BLAKE3 base proving and benchmarking.
//! The outer CLI owns atomic publication; only verified bytes reach its temp file.
const std = @import("std");
const stwo = @import("stwo");
const build_identity = @import("build_identity");
const identity = @import("artifact_validation.zig");
const pcs_profile = @import("pcs_profile.zig");
const request = @import("blake3_execution_request.zig");

pub fn run(comptime Engine: type, comptime backend: anytype, comptime ethereum: bool, a: std.mem.Allocator, elf_path: []const u8, input_path: ?[]const u8, options: anytype, process: identity.ProcessIdentity) ![]u8 {
    const artifact = if (ethereum) stwo.frontends.riscv.prover_mod.blake3_ethereum_artifact else stwo.frontends.riscv.prover_mod.blake3_execution_artifact;
    const pools = @import("stwo_prover_engine").work_pool;
    var pool: if (ethereum) pools.WorkPool else void = undefined;
    if (ethereum) try pool.initInPlaceWithOptions(.{ .worker_count = @max(1, @min(16, try std.Thread.getCpuCount())), .backing_allocator = a });
    defer if (ethereum) pool.deinit();
    var binding: if (ethereum) pools.ScopedPoolBinding else void = if (ethereum) try pools.ScopedPoolBinding.init(&pool) else {};
    defer if (ethereum) binding.deinit();
    const suite = stwo.core.proof_suites.Blake3;
    if (comptime Engine.Hasher != suite.Hasher or Engine.Channel != suite.Channel or Engine.MerkleChannel != suite.MerkleChannel) return error.ProofSuiteMismatch;
    switch (options.mode) {
        .prove => if (options.proof_temporary == null) return error.MissingProofOutput,
        .bench => {},
    }
    const limits = artifact.Limits{};
    const elf = try std.fs.cwd().readFileAlloc(a, elf_path, limits.max_elf_bytes);
    defer a.free(elf);
    const input: []const u8 = if (input_path) |path| try std.fs.cwd().readFileAlloc(a, path, limits.manifest.statement.max_input_bytes) else &.{};
    defer if (input_path != null) a.free(input);
    const warmups: usize = switch (options.mode) {
        .prove => 0,
        .bench => |b| b.warmups,
    };
    const samples: usize = switch (options.mode) {
        .prove => 1,
        .bench => |b| b.samples,
    };
    if (samples == 0) return error.NoBenchmarkSamples;
    const timings = try a.alloc(request.Timing, samples);
    defer a.free(timings);
    const devices = try a.alloc(request.DeviceCounts, samples);
    defer a.free(devices);
    const ordered = try a.alloc(u64, samples);
    defer a.free(ordered);
    var expected_statement: ?[32]u8 = null;
    var expected_transcript: ?[32]u8 = null;
    var steps: usize = 0;
    var proof_bytes: usize = 0;
    var proof_sha256: [32]u8 = undefined;
    var verified_public: stwo.frontends.riscv.prover_mod.blake3_verified_public = undefined;
    const resource_usage = @import("stwo_prover_engine").measurement.resource_report;
    const resources_before = resource_usage.capture();
    const count = try std.math.add(usize, warmups, samples);
    for (0..count) |index| {
        var result = try request.execute(Engine, backend == .metal, ethereum, a, elf, input, pcs_profile.select(options.protocol));
        defer result.deinit(a);
        if (expected_statement) |expected| {
            if (!std.mem.eql(u8, &expected, &result.artifact.statement_id)) return error.NonDeterministicStatement;
            if (!std.mem.eql(u8, &expected_transcript.?, &result.transcript)) return error.NonDeterministicTranscript;
            if (steps != result.steps) return error.NonDeterministicExecution;
        } else {
            expected_statement = result.artifact.statement_id;
            expected_transcript = result.transcript;
            steps = result.steps;
        }
        if (index < warmups) continue;
        timings[index - warmups] = result.timing;
        devices[index - warmups] = result.device;
        ordered[index - warmups] = result.timing.total_ns;
        if (index + 1 == count) {
            verified_public = result.public;
            proof_bytes = result.artifact.bytes.len;
            std.crypto.hash.sha2.Sha256.hash(result.artifact.bytes, &proof_sha256, .{});
            if (options.proof_temporary) |path| {
                var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
                defer file.close();
                try file.writeAll(result.artifact.bytes);
            }
        }
    }
    std.mem.sort(u64, ordered, {}, std.sort.asc(u64));
    const middle = samples / 2;
    const median_ns: f64 = if (samples % 2 != 0) @floatFromInt(ordered[middle]) else @as(f64, @floatFromInt(ordered[middle - 1])) / 2 + @as(f64, @floatFromInt(ordered[middle])) / 2;
    const statement_hex = std.fmt.bytesToHex(expected_statement.?, .lower);
    const transcript_hex = std.fmt.bytesToHex(expected_transcript.?, .lower);
    const proof_hex = std.fmt.bytesToHex(proof_sha256, .lower);
    const output_hex = std.fmt.bytesToHex(verified_public.output_sha256, .lower);
    const elf_hex = std.fmt.bytesToHex(verified_public.elf_sha256, .lower);
    const input_hex = std.fmt.bytesToHex(verified_public.input_sha256, .lower);
    const executable_hex = std.fmt.bytesToHex(process.executable_sha256, .lower);
    return std.json.Stringify.valueAlloc(a, .{
        .schema = "riscv_full_width_execution_v2",
        .mode = @tagName(options.mode),
        .backend = @tagName(backend),
        .proof_suite = "blake3",
        .execution_profile = if (ethereum) "rv32im_zkvm_ethereum_v1" else "rv32im_zkvm_v1",
        .artifact_magic = artifact.MAGIC,
        .security_policy = @tagName(options.protocol),
        .release_status = "experimental_full_width",
        .experimental = options.experimental,
        .verified_in_process = true,
        .recursion_enabled = false,
        .warmups = warmups,
        .samples = samples,
        .verified_samples = samples,
        .total_steps = steps,
        .timing_partition = "execution+witness+admission+proving+artifact_encoding+fresh_verification",
        .timing_unit = "nanoseconds",
        .timings = timings,
        .proof_device_counts = devices,
        .profile_kind = "phase_timings",
        .profiled = switch (options.mode) {
            .prove => false,
            .bench => |b| b.profiled,
        },
        .median_seconds = median_ns / std.time.ns_per_s,
        .statement_blake3 = &statement_hex,
        .transcript_digest_blake3 = &transcript_hex,
        .proof_bytes = proof_bytes,
        .pcs_config = pcs_profile.select(options.protocol),
        .output_len = verified_public.output_len,
        .output_sha256 = &output_hex,
        .elf_sha256 = &elf_hex,
        .input_sha256 = &input_hex,
        .resources = resource_usage.report(resources_before, resource_usage.capture()),
        .proof_sha256 = &proof_hex,
        .proof_path = options.proof_report_path,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_dirty = build_identity.implementation_dirty,
        .executable_sha256 = &executable_hex,
    }, .{ .emit_null_optional_fields = false });
}
