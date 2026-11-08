//! One fresh-process, single-arm, independently verified C-013 CPU attempt.
//!
//! The child never runs the opposite arm. A capture orchestrator must compare
//! pinned input/output identities, retain launch order, and account for every
//! exit. This executable is infrastructure for that orchestrator, not itself a
//! performance verdict or receipt.

const std = @import("std");
const build_identity = @import("build_identity");
const core = @import("stwo_core");
const prover_engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const attempt = @import("proof_attempt.zig");
const corpus = @import("corpus.zig");
const protocol = @import("capture_protocol.zig");
const schedule = @import("capture_schedule.zig");

const process_usage = prover_engine.measurement.process_usage;

/// Receipt children reserve stdout for one JSON record and stderr for actual
/// failures. Imported informational logs are deliberately suppressed.
pub const std_options: std.Options = .{ .log_level = .warn };

const functional_config = core.pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const options = protocol.parseOptions(args) catch |failure| {
        try usage(std.fs.File.stderr().deprecatedWriter());
        if (failure == error.HelpRequested) return;
        return failure;
    };
    if (options.phase != .diagnostic) try validateScheduledAttempt(options);

    const executable_digest = try hashSelf();
    try requireDigest(
        options.expected_executable_sha256,
        executable_digest,
        error.ExecutableDigestMismatch,
    );
    const elf = try std.fs.cwd().readFileAlloc(
        allocator,
        options.elf_path,
        16 * 1024 * 1024,
    );
    defer allocator.free(elf);
    const input = try corpus.makeInput(allocator, options.calls);
    defer allocator.free(input);
    const max_steps = options.max_steps orelse
        try corpus.defaultMaxStepsForBackground(
            options.calls,
            options.shape.backgroundPermutationsPerCall(),
        );

    const input_digest = digestBytes(input);
    try requireDigest(
        options.expected_input_sha256,
        input_digest,
        error.CorpusDigestMismatch,
    );
    const elf_digest = digestBytes(elf);
    try requireDigest(
        options.expected_elf_sha256,
        elf_digest,
        error.ElfDigestMismatch,
    );
    const pcs_config = switch (options.security) {
        .functional => functional_config,
        .secure => frontend.prover_mod.SECURE_PCS_CONFIG,
    };

    const resources_before = try process_usage.sample();
    var metrics = switch (options.arm) {
        .software => try attempt.software(
            allocator,
            elf,
            input,
            max_steps,
            pcs_config,
        ),
        .precompile => try attempt.precompile(
            allocator,
            elf,
            input,
            max_steps,
            pcs_config,
        ),
    };
    defer metrics.deinit(allocator);
    const resources_after = try process_usage.sample();
    const resources = try process_usage.difference(
        resources_before,
        resources_after,
    );
    if (options.phase.requiresPins() and !resources.available())
        return error.RequiredProcessUsageUnavailable;

    const output_digest = digestBytes(metrics.output);
    try requireDigest(
        options.expected_output_sha256,
        output_digest,
        error.CorpusDigestMismatch,
    );
    const input_hex = std.fmt.bytesToHex(input_digest, .lower);
    const output_hex = std.fmt.bytesToHex(output_digest, .lower);
    const elf_hex = std.fmt.bytesToHex(elf_digest, .lower);
    const executable_hex = std.fmt.bytesToHex(executable_digest, .lower);
    const proof_hex = std.fmt.bytesToHex(metrics.proof_sha256, .lower);
    const report = protocol.Report{
        .schema = protocol.schema,
        .status = "verified",
        .arm = @tagName(options.arm),
        .security = @tagName(options.security),
        .phase = @tagName(options.phase),
        .shape = @tagName(options.shape),
        .background_permutations_per_call = options.shape.backgroundPermutationsPerCall(),
        .schedule_sha256 = if (options.phase.requiresPins())
            protocol.capture_schedule_sha256
        else
            null,
        .calls = options.calls,
        .sample_index = options.sample_index,
        .max_steps = max_steps,
        .input_bytes = input.len,
        .output_bytes = metrics.output.len,
        .extension_calls = if (options.arm == .precompile) options.calls else 0,
        .input_sha256 = &input_hex,
        .output_sha256 = &output_hex,
        .elf_sha256 = &elf_hex,
        .executable_sha256 = &executable_hex,
        .proof_sha256 = &proof_hex,
        .implementation_commit = build_identity.implementation_commit,
        .implementation_tree = if (build_identity.implementation_tree_available)
            build_identity.implementation_tree
        else
            null,
        .implementation_dirty = build_identity.implementation_dirty,
        .dirty_content_sha256 = if (build_identity.dirty_content_sha256_available)
            build_identity.dirty_content_sha256
        else
            null,
        .pcs = .{
            .pow_bits = pcs_config.pow_bits,
            .log_blowup_factor = pcs_config.fri_config.log_blowup_factor,
            .queries = pcs_config.fri_config.n_queries,
            .fold_step = pcs_config.fri_config.fold_step,
        },
        .metrics = .{
            .execution_steps = metrics.execution_steps,
            .execution_ns = metrics.execution_ns,
            .proving_ns = metrics.proving_ns,
            .proof_encoding_ns = metrics.proof_encoding_ns,
            .verification_ns = metrics.verification_ns,
            .verified_request_ns = metrics.verified_request_ns,
            .proof_wire_bytes = metrics.proof_wire_bytes,
            .preprocessed_cells = metrics.preprocessed_cells,
            .main_cells = metrics.main_cells,
            .interaction_cells = metrics.interaction_cells,
        },
        .resources = .{
            .scope = protocol.resource_scope,
            .source = @tagName(resources.source),
            .lifetime_peak_physical_footprint_bytes = resources.lifetime_peak_physical_footprint_bytes,
            .process_cpu_ns = resources.process_cpu_ns,
            .energy_nj = resources.energy_nj,
            .instructions = resources.instructions,
            .cycles = resources.cycles,
            .unavailable_reason = resources.unavailable_reason,
        },
    };
    try report.validate();
    try writeJsonLine(report);
}

fn validateScheduledAttempt(options: protocol.Options) !void {
    return schedule.validateAttempt(
        options.sample_index,
        options.shape,
        options.calls,
        options.phase,
        options.arm,
    );
}

fn requireDigest(
    expected: ?[32]u8,
    actual: [32]u8,
    failure: anyerror,
) !void {
    if (expected) |pinned| {
        if (!std.mem.eql(u8, &pinned, &actual))
            return failure;
    }
}

fn digestBytes(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashSelf() ![32]u8 {
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fs.selfExePath(&path_buffer);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0)
        return error.InvalidExecutable;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var measured: u64 = 0;
    while (true) {
        const count = try file.read(&buffer);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        measured = try std.math.add(u64, measured, count);
    }
    const after = try file.stat();
    if (measured != before.size or before.size != after.size or
        before.inode != after.inode or before.mtime != after.mtime)
    {
        return error.ExecutableChangedDuringMeasurement;
    }
    return hash.finalResult();
}

fn writeJsonLine(value: anytype) !void {
    var buffer: [16 * 1024]u8 = undefined;
    var output = std.fs.File.stdout().writer(&buffer);
    try std.json.Stringify.value(value, .{}, &output.interface);
    try output.interface.writeByte('\n');
    try output.interface.flush();
}

fn usage(writer: anytype) !void {
    try writer.writeAll(
        \\Usage: riscv-poseidon2-proof-child --arm software|precompile
        \\       --security functional|secure
        \\       --phase diagnostic|calibration|warmup|measured
        \\       --shape core_only|balanced_core_and_poseidon2|poseidon2_dominant
        \\       --elf PATH --calls N
        \\       --sample-index N [--max-steps N]
        \\       [--schedule-sha256 HEX]
        \\       [--expected-input-sha256 HEX --expected-output-sha256 HEX]
        \\       [--expected-elf-sha256 HEX]
        \\       [--expected-executable-sha256 HEX]
        \\
        \\Non-diagnostic attempts require the exact schedule and corpus pins.
        \\This child
        \\runs and independently verifies exactly one arm in one process; it
        \\does not compute a C-013 verdict.
        \\
    );
}
